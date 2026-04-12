#include "common/logger.h"
#include "common/utils.h"
#include "ingestion/ring_buffer.h"
#include "ingestion/syslog_listener.h"
#include "ingestion/http_poller.h"
#include "ingestion/connector_manager.h"
#include "parser/parser_registry.h"
#include "rules/rule_engine.h"
#include "storage/postgres_storage_engine.h"
#include "api/server.h"
#include "auth/auth.h"
#include "auth/smtp.h"

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

using namespace outpost;

// ── Global shutdown flag ──
static std::atomic<bool> g_running{true};

void signal_handler(int sig) {
    LOG_INFO("Received signal {}, shutting down...", sig);
    g_running.store(false, std::memory_order_relaxed);
}

/// Create a fallback event from a hinted connector message
Event make_hinted_event(const RawMessage& msg, SourceType source_type) {
    Event e;
    e.event_id    = generate_uuid();
    e.timestamp   = now_ms();
    e.received_at = e.timestamp;
    e.source_type = source_type;
    e.source_host = msg.source_addr;
    e.raw         = msg.as_string();
    e.category    = Category::Network;
    e.severity    = Severity::Info;
    e.action      = "api_event";

    try {
        auto j = nlohmann::json::parse(e.raw);
        if (j.is_object()) {
            if (j.contains("name"))
                e.resource = j["name"].get<std::string>();
            else if (j.contains("_id"))
                e.resource = j["_id"].get<std::string>();
            if (j.contains("ip") || j.contains("ipAddress"))
                e.src_ip = j.value("ip", j.value("ipAddress", ""));
            if (j.contains("mac"))
                e.resource = j.value("hostname", j.value("name", j["mac"].get<std::string>()));
            e.metadata = j;
        }
    } catch (...) {}

    return e;
}

/// Parser worker thread: drains ring buffer, parses, stores, evaluates rules
void parser_worker(RingBuffer<>& buffer, PostgresStorageEngine& storage,
                   RuleEngine& rule_engine,
                   std::vector<std::unique_ptr<Parser>>& parsers,
                   std::atomic<uint64_t>& parsed_count) {
    while (g_running.load(std::memory_order_relaxed)) {
        auto msg = buffer.try_pop();
        if (!msg) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            continue;
        }

        // Check if this message has a source hint from a connector
        std::string hint(msg->source_hint);
        SourceType hinted_type = source_type_from_string(hint);
        bool has_hint = (hinted_type != SourceType::Unknown);

        // Try each parser until one succeeds
        bool parsed = false;
        for (auto& parser : parsers) {
            auto event = parser->parse(*msg);
            if (event) {
                // If the event has no geo data, check for connector-injected fallback location
                if (!event->metadata.contains("latitude") || !event->metadata.contains("longitude")) {
                    if (event->metadata.contains("_connector_latitude") &&
                        event->metadata.contains("_connector_longitude")) {
                        event->metadata["latitude"]  = event->metadata["_connector_latitude"];
                        event->metadata["longitude"] = event->metadata["_connector_longitude"];
                        if (event->metadata.contains("_connector_city")) {
                            event->metadata["city"] = event->metadata["_connector_city"];
                        }
                        if (!event->metadata.contains("geo_type")) {
                            event->metadata["geo_type"] = "event";
                        }
                    }
                }
                // Clean up internal connector tags
                event->metadata.erase("_connector_latitude");
                event->metadata.erase("_connector_longitude");
                event->metadata.erase("_connector_city");

                storage.insert(*event);
                rule_engine.evaluate(*event);
                parsed_count.fetch_add(1, std::memory_order_relaxed);
                parsed = true;
                break;
            }
        }

        if (!parsed) {
            // No parser claimed it — use the source hint if available
            Event e = has_hint
                ? make_hinted_event(*msg, hinted_type)
                : [&]() {
                    Event ev;
                    ev.event_id    = generate_uuid();
                    ev.timestamp   = now_ms();
                    ev.received_at = ev.timestamp;
                    ev.source_type = SourceType::Unknown;
                    ev.source_host = msg->source_addr;
                    ev.raw         = msg->as_string();
                    ev.category    = Category::Unknown;
                    return ev;
                }();

            storage.insert(e);
            rule_engine.evaluate(e);
            parsed_count.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

/// Periodic flush thread
void flush_worker(PostgresStorageEngine& storage, int interval_ms) {
    while (g_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        storage.flush();
    }
    storage.flush();  // final flush on shutdown
}

int main(int argc, char* argv[]) {
    // ── Initialize ──
    init_logger("", spdlog::level::info);

    
    LOG_INFO("╔═══════════════════════════════════════════╗");
    LOG_INFO("║         OUTPOST SIEM v0.1.0               ║");
    LOG_INFO("║          A work in progress               ║");
    LOG_INFO("╚═══════════════════════════════════════════╝");
    LOG_INFO("============================================================================================");
    LOG_INFO("I would rather have questions that can't be answered than answers that can't be questioned.");
    LOG_INFO("============================================================================================");
    // Signal handling
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // ── Load configuration from YAML ──
    std::string config_path = "./config/outpost.yaml";
    if (argc > 1) config_path = argv[1];

    YAML::Node config;
    try {
        config = YAML::LoadFile(config_path);
        LOG_INFO("Loaded configuration from {}", config_path);
    } catch (const YAML::Exception& e) {
        LOG_WARN("Could not load {}: {} — using defaults", config_path, e.what());
    }

    // ── Components ──
    RingBuffer<> buffer;  // 65536-slot ring buffer

    // Storage (PostgreSQL) - YAML config with env var overrides
    PostgresConfig storage_config;

    auto pg = config["postgres"];
    storage_config.host     = pg && pg["host"]     ? pg["host"].as<std::string>()     : "localhost";
    storage_config.port     = pg && pg["port"]      ? pg["port"].as<int>()             : 5432;
    storage_config.dbname   = pg && pg["database"]  ? pg["database"].as<std::string>() : "outpost";
    storage_config.user     = pg && pg["user"]      ? pg["user"].as<std::string>()     : "postgres";
    storage_config.password = pg && pg["password"]  ? pg["password"].as<std::string>() : "";
    storage_config.batch_size       = pg && pg["batch_size"]       ? pg["batch_size"].as<int>()       : 1000;
    storage_config.flush_interval_ms = pg && pg["flush_interval_ms"] ? pg["flush_interval_ms"].as<int>() : 1000;

    // Environment variables override YAML (standard PG* vars)
    if (const char* v = std::getenv("PGHOST"))     storage_config.host     = v;
    if (const char* v = std::getenv("PGPORT"))     storage_config.port     = std::stoi(v);
    if (const char* v = std::getenv("PGDATABASE")) storage_config.dbname   = v;
    if (const char* v = std::getenv("PGUSER"))     storage_config.user     = v;
    if (const char* v = std::getenv("PGPASSWORD")) storage_config.password = v;
    if (const char* v = std::getenv("PGSSLMODE"))  storage_config.sslmode  = v;

    LOG_INFO("PostgreSQL Configuration:");
    LOG_INFO("  Host:     {}", storage_config.host);
    LOG_INFO("  Port:     {}", storage_config.port);
    LOG_INFO("  Database: {}", storage_config.dbname);
    LOG_INFO("  User:     {}", storage_config.user);
    PostgresStorageEngine storage(storage_config);
    if (!storage.init()) {
        LOG_CRITICAL("Failed to initialize PostgreSQL storage engine");
        return 1;
    }

    // Parser registry (order matters — specific parsers first, catch-all last)
    ParserRegistry parser_registry;
    parser_registry.register_defaults();
    auto& parsers = parser_registry.parsers();

    // Syslog listener
    SyslogConfig syslog_config;
    syslog_config.udp_port = 5514;  // non-privileged port for dev; use 514 in prod
    syslog_config.tcp_port = 5514;
    SyslogListener listener(buffer, syslog_config);

    // HTTP Poller (M365 + Azure) - load from YAML
    HttpPollerConfig poller_config;
    auto integ = config["integrations"];
    if (integ && integ["m365"]) {
        auto m = integ["m365"];
        poller_config.m365_enabled = m["enabled"] ? m["enabled"].as<bool>() : false;
        poller_config.m365_oauth.tenant_id     = m["tenant_id"]     ? m["tenant_id"].as<std::string>()     : "";
        poller_config.m365_oauth.client_id     = m["client_id"]     ? m["client_id"].as<std::string>()     : "";
        poller_config.m365_oauth.client_secret = m["client_secret"] ? m["client_secret"].as<std::string>() : "";
        poller_config.m365_poll_interval_sec   = m["poll_interval_sec"] ? m["poll_interval_sec"].as<int>() : 60;
    }
    if (integ && integ["azure"]) {
        auto a = integ["azure"];
        poller_config.azure_enabled = a["enabled"] ? a["enabled"].as<bool>() : false;
        poller_config.azure_oauth.tenant_id     = a["tenant_id"]     ? a["tenant_id"].as<std::string>()     : "";
        poller_config.azure_oauth.client_id     = a["client_id"]     ? a["client_id"].as<std::string>()     : "";
        poller_config.azure_oauth.client_secret = a["client_secret"] ? a["client_secret"].as<std::string>() : "";
        poller_config.azure_subscription_id     = a["subscription_id"] ? a["subscription_id"].as<std::string>() : "";
        poller_config.azure_poll_interval_sec   = a["poll_interval_sec"] ? a["poll_interval_sec"].as<int>() : 60;
    }
    HttpPoller poller(buffer, poller_config);

    // Connector manager (generic REST API polling for DB-configured connectors)
    ConnectorManager connector_mgr(buffer, storage);

    // Rule engine
    RuleEngine rule_engine(storage);
    rule_engine.load_rules("./config/rules");

    // Auth config
    AuthConfig auth_config;
    auto auth_node = config["auth"];
    if (auth_node) {
        auth_config.default_admin_user = auth_node["default_admin_user"] ? auth_node["default_admin_user"].as<std::string>() : "admin";
        auth_config.default_admin_pass = auth_node["default_admin_pass"] ? auth_node["default_admin_pass"].as<std::string>() : "outpost";
        auth_config.session_ttl_hours  = auth_node["session_ttl_hours"]  ? auth_node["session_ttl_hours"].as<int>()          : 24;
    }

    // Create default admin user if no users exist
    if (storage.user_count() == 0) {
        auto salt = generate_salt();
        auto hash = hash_password(auth_config.default_admin_pass, salt);
        storage.create_user(generate_uuid(), auth_config.default_admin_user, "admin@outpost.local", hash, salt, "admin");
        LOG_WARN("Default admin account created (user: {}). Change the password immediately!",
                 auth_config.default_admin_user);
    }

    // API server
    ApiConfig api_config;
    api_config.port = 8080;
    // CORS origin: env var > YAML > default "*"
    auto api_node = config["api"];
    if (api_node && api_node["cors_origin"]) {
        api_config.cors_origin = api_node["cors_origin"].as<std::string>();
    }
    if (const char* v = std::getenv("OUTPOST_CORS_ORIGIN")) api_config.cors_origin = v;

    // HEC token: YAML > env var > auto-generated
    auto hec_node = config["hec"];
    if (hec_node && hec_node["token"]) {
        api_config.hec_token = hec_node["token"].as<std::string>();
    }
    if (const char* v = std::getenv("OUTPOST_HEC_TOKEN")) api_config.hec_token = v;
    if (api_config.hec_token.empty()) {
        api_config.hec_token = generate_uuid();
        LOG_WARN("╔══════════════════════════════════════════════════════════╗");
        LOG_WARN("║  HEC token auto-generated (not set in outpost.yaml):     ║");
        LOG_WARN("║  {}  ║", api_config.hec_token);
        LOG_WARN("║  Add to config:  hec:                                    ║");
        LOG_WARN("║                    token: {}  ║", api_config.hec_token);
        LOG_WARN("╚══════════════════════════════════════════════════════════╝");
    } else {
        LOG_INFO("HEC endpoint enabled (token configured)");
    }

    // SMTP config (for password reset emails)
    SmtpConfig smtp_config;
    auto smtp_node = config["smtp"];
    if (smtp_node) {
        smtp_config.enabled   = smtp_node["enabled"]   ? smtp_node["enabled"].as<bool>()         : false;
        smtp_config.host      = smtp_node["host"]       ? smtp_node["host"].as<std::string>()      : "";
        smtp_config.port      = smtp_node["port"]       ? smtp_node["port"].as<int>()              : 25;
        smtp_config.username  = smtp_node["username"]   ? smtp_node["username"].as<std::string>()  : "";
        smtp_config.password  = smtp_node["password"]   ? smtp_node["password"].as<std::string>()  : "";
        smtp_config.from      = smtp_node["from"]       ? smtp_node["from"].as<std::string>()      : "noreply@outpost.local";
        smtp_config.from_name = smtp_node["from_name"]  ? smtp_node["from_name"].as<std::string>() : "Firewatch SIEM";
        smtp_config.use_ssl   = smtp_node["use_ssl"]    ? smtp_node["use_ssl"].as<bool>()          : false;
        smtp_config.base_url  = smtp_node["base_url"]   ? smtp_node["base_url"].as<std::string>()  : "";
    }
    if (smtp_config.enabled) {
        LOG_INFO("SMTP configured: {}:{} (ssl={}) from={}",
                 smtp_config.host, smtp_config.port, smtp_config.use_ssl, smtp_config.from);
    }

    ApiServer api(storage, buffer, poller, rule_engine, connector_mgr, config_path, auth_config, api_config, smtp_config);

    // ── Start everything ──
    listener.start();
    poller.start();
    connector_mgr.start();
    api.start();

    // Parser worker threads
    std::atomic<uint64_t> parsed_count{0};
    constexpr int NUM_PARSER_WORKERS = 2;
    std::vector<std::thread> parser_threads;
    for (int i = 0; i < NUM_PARSER_WORKERS; ++i) {
        parser_threads.emplace_back(parser_worker,
            std::ref(buffer), std::ref(storage),
            std::ref(rule_engine),
            std::ref(parsers), std::ref(parsed_count));
    }

    // Flush thread (every 1 second)
    std::thread flusher(flush_worker, std::ref(storage), 1000);

    LOG_INFO("Outpost is running.");
    LOG_INFO("  Syslog UDP/TCP: port {}", syslog_config.udp_port);
    LOG_INFO("  REST API:       http://{}:{}/api/health", api_config.bind_address, api_config.port);
    LOG_INFO("  PostgreSQL:     {}:{}/{}", storage_config.host, storage_config.port, storage_config.dbname);
    LOG_INFO("  Detection rules: {}", rule_engine.rule_count());
    LOG_INFO("Press Ctrl+C to stop.");

    // ── Main loop: periodic stats ──
    while (g_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!g_running.load()) break;

        LOG_INFO("Stats | syslog: {} | m365: {} | azure: {} | parsed: {} | stored: {} | alerts: {} | buffer: {}/{} | drops: {}",
                 listener.total_received(),
                 poller.m365_events(),
                 poller.azure_events(),
                 parsed_count.load(),
                 storage.total_inserted(),
                 rule_engine.alerts_fired(),
                 buffer.size_approx(), buffer.capacity(),
                 buffer.drop_count());
    }

    // ── Shutdown ──
    LOG_INFO("Shutting down...");
    listener.stop();
    poller.stop();
    connector_mgr.stop();
    api.stop();

    for (auto& t : parser_threads) {
        if (t.joinable()) t.join();
    }
    if (flusher.joinable()) flusher.join();

    LOG_INFO("Outpost stopped. Total events processed: {}", storage.total_inserted());
    return 0;
}
