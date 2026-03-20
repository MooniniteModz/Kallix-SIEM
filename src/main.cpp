#include "common/logger.h"
#include "common/utils.h"
#include "ingestion/ring_buffer.h"
#include "ingestion/syslog_listener.h"
#include "ingestion/http_poller.h"
#include "parser/fortigate_parser.h"
#include "parser/windows_parser.h"
#include "parser/m365_parser.h"
#include "parser/azure_parser.h"
#include "parser/syslog_parser.h"
#include "rules/rule_engine.h"
#include "storage/postgres_storage_engine.h"
#include "api/server.h"

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

/// Parser worker thread: drains ring buffer, parses, stores, evaluates rules
void parser_worker(RingBuffer<>& buffer, PostgresStorageEngine& storage,
                   RuleEngine& rule_engine,
                   std::vector<std::unique_ptr<Parser>>& parsers,
                   std::atomic<uint64_t>& parsed_count) {
    while (g_running.load(std::memory_order_relaxed)) {
        auto msg = buffer.try_pop();
        if (!msg) {
            // No data — brief sleep to avoid busy-spinning
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            continue;
        }

        // Try each parser until one succeeds
        bool parsed = false;
        for (auto& parser : parsers) {
            auto event = parser->parse(*msg);
            if (event) {
                storage.insert(*event);
                rule_engine.evaluate(*event);
                parsed_count.fetch_add(1, std::memory_order_relaxed);
                parsed = true;
                break;
            }
        }

        if (!parsed) {
            // Fallback: store as raw unknown event
            Event e;
            e.event_id    = generate_uuid();
            e.timestamp   = now_ms();
            e.received_at = e.timestamp;
            e.source_type = SourceType::Unknown;
            e.source_host = msg->source_addr;
            e.raw         = msg->as_string();
            e.category    = Category::Unknown;
            storage.insert(e);
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

    // ── Components ──
    RingBuffer<> buffer;  // 65536-slot ring buffer

    // Storage (PostgreSQL) - Read from environment variables
    // This allows flexible configuration across dev/test/prod without recompiling
    PostgresConfig storage_config;

    // Database host (defaults to domain name, can be overridden by env var)
    const char* pg_host = std::getenv("PGHOST");
    storage_config.host = pg_host ? std::string(pg_host) : "outpost.otl-upt.com";

    // Database port (defaults to 5432)
    const char* pg_port = std::getenv("PGPORT");
    storage_config.port = pg_port ? std::stoi(std::string(pg_port)) : 5432;

    // Database name (defaults to "outpost")
    const char* pg_db = std::getenv("PGDATABASE");
    storage_config.dbname = pg_db ? std::string(pg_db) : "outpost";

    // Database user (defaults to "postgres")
    const char* pg_user = std::getenv("PGUSER");
    storage_config.user = pg_user ? std::string(pg_user) : "postgres";

    // Database password (must be set via environment variable for security)
    const char* pg_pass = std::getenv("PGPASSWORD");
    storage_config.password = pg_pass ? std::string(pg_pass) : "";

    // Log configuration being used
    LOG_INFO("PostgreSQL Configuration:");
    LOG_INFO("  Host:     {}", storage_config.host);
    LOG_INFO("  Port:     {}", storage_config.port);
    LOG_INFO("  Database: {}", storage_config.dbname);
    LOG_INFO("  User:     {}", storage_config.user);
    storage_config.batch_size = 1000;
    PostgresStorageEngine storage(storage_config);
    if (!storage.init()) {
        LOG_CRITICAL("Failed to initialize PostgreSQL storage engine");
        return 1;
    }

    // Parsers (order matters — more specific parsers first)
    std::vector<std::unique_ptr<Parser>> parsers;
    parsers.push_back(std::make_unique<FortiGateParser>());
    parsers.push_back(std::make_unique<WindowsParser>());
    parsers.push_back(std::make_unique<M365Parser>());
    parsers.push_back(std::make_unique<AzureParser>());
    parsers.push_back(std::make_unique<SyslogParser>());  // catch-all last

    // Syslog listener
    SyslogConfig syslog_config;
    syslog_config.udp_port = 5514;  // non-privileged port for dev; use 514 in prod
    syslog_config.tcp_port = 5514;
    SyslogListener listener(buffer, syslog_config);

    // HTTP Poller (M365 + Azure; disabled by default, enable in config)
    HttpPollerConfig poller_config;
    // These would be loaded from outpost.yaml in a full implementation.
    // For now, they default to disabled. Set m365_enabled/azure_enabled = true
    // and provide OAuth credentials to activate.
    HttpPoller poller(buffer, poller_config);

    // Rule engine
    RuleEngine rule_engine(storage);
    rule_engine.load_rules("./config/rules");

    // API server
    ApiConfig api_config;
    api_config.port = 8080;
    ApiServer api(storage, buffer, api_config);

    // ── Start everything ──
    listener.start();
    poller.start();
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
    api.stop();

    for (auto& t : parser_threads) {
        if (t.joinable()) t.join();
    }
    if (flusher.joinable()) flusher.join();

    LOG_INFO("Outpost stopped. Total events processed: {}", storage.total_inserted());
    return 0;
}
