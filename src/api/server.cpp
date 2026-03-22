#include "api/server.h"
#include "common/event.h"
#include "common/logger.h"
#include "common/utils.h"
#include "rules/rule.h"

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <fstream>

namespace outpost {

static int64_t s_start_time = 0;

ApiServer::ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer,
                     HttpPoller& poller, const std::string& config_path,
                     const ApiConfig& config)
    : storage_(storage), buffer_(buffer), poller_(poller),
      config_path_(config_path), config_(config) {
    s_start_time = now_ms();
}

ApiServer::~ApiServer() { stop(); }

void ApiServer::start() {
    if (running_.exchange(true)) return;
    setup_routes();
    thread_ = std::thread([this]() {
        LOG_INFO("API server starting on {}:{}", config_.bind_address, config_.port);
        server_.listen(config_.bind_address, config_.port);
    });
}

void ApiServer::stop() {
    if (!running_.exchange(false)) return;
    server_.stop();
    if (thread_.joinable()) thread_.join();
    LOG_INFO("API server stopped");
}

void ApiServer::setup_routes() {
    server_.Get("/api/health", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json health = {
            {"status", "ok"}, {"version", "0.2.0"},
            {"uptime_ms", now_ms() - s_start_time},
            {"buffer_usage", buffer_.size_approx()},
            {"buffer_capacity", buffer_.capacity()},
            {"buffer_drops", buffer_.drop_count()},
            {"events_stored_today", storage_.count_today()},
            {"total_events_inserted", storage_.total_inserted()}
        };
        res.set_content(health.dump(2), "application/json");
    });

    server_.Get("/api/events", [this](const httplib::Request& req, httplib::Response& res) {
        int64_t start_ms = 0, end_ms = now_ms();
        std::string keyword; int limit = 100, offset = 0;
        if (req.has_param("start"))  start_ms = std::stoll(req.get_param_value("start"));
        if (req.has_param("end"))    end_ms   = std::stoll(req.get_param_value("end"));
        if (req.has_param("q"))      keyword  = req.get_param_value("q");
        if (req.has_param("limit"))  limit    = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset   = std::stoi(req.get_param_value("offset"));
        auto events = storage_.query(start_ms, end_ms, keyword, limit, offset);
        nlohmann::json result = nlohmann::json::array();
        for (const auto& e : events) result.push_back(event_to_json(e));
        res.set_content(nlohmann::json({{"count", events.size()}, {"events", result}}).dump(), "application/json");
    });

    server_.Get("/api/stats", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json stats = {
            {"events_today", storage_.count_today()},
            {"total_inserted", storage_.total_inserted()},
            {"buffer_size", buffer_.size_approx()},
            {"buffer_capacity", buffer_.capacity()},
            {"buffer_drops", buffer_.drop_count()},
            {"uptime_ms", now_ms() - s_start_time}
        };
        res.set_content(stats.dump(2), "application/json");
    });

    server_.Get("/api/stats/sources", [this](const httplib::Request&, httplib::Response& res) {
        auto data = storage_.count_by_field("source_type");
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/severity", [this](const httplib::Request&, httplib::Response& res) {
        auto data = storage_.count_by_field("severity");
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/categories", [this](const httplib::Request&, httplib::Response& res) {
        auto data = storage_.count_by_field("category");
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/top-ips", [this](const httplib::Request& req, httplib::Response& res) {
        int limit = 10;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        auto data = storage_.top_values("src_ip", limit);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/top-users", [this](const httplib::Request& req, httplib::Response& res) {
        int limit = 10;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        auto data = storage_.top_values("user_name", limit);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/top-actions", [this](const httplib::Request& req, httplib::Response& res) {
        int limit = 10;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        auto data = storage_.top_values("action", limit);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/timeline", [this](const httplib::Request& req, httplib::Response& res) {
        int hours = 24;
        if (req.has_param("hours")) hours = std::stoi(req.get_param_value("hours"));
        auto data = storage_.event_timeline(hours);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/alerts", [this](const httplib::Request& req, httplib::Response& res) {
        int limit = 100;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        auto alerts = storage_.get_alerts(limit);
        nlohmann::json result = nlohmann::json::array();
        for (const auto& a : alerts) {
            result.push_back({
                {"alert_id", a.alert_id},
                {"rule_id", a.rule_id},
                {"rule_name", a.rule_name},
                {"severity", to_string(a.severity)},
                {"description", a.description},
                {"event_ids", a.event_ids},
                {"created_at", a.created_at},
                {"acknowledged", a.acknowledged}
            });
        }
        res.set_content(nlohmann::json({{"count", alerts.size()}, {"alerts", result}}).dump(), "application/json");
    });

    // ── Integration config endpoints ──

    server_.Get("/api/integrations", [this](const httplib::Request&, httplib::Response& res) {
        // Read current integration config from YAML
        nlohmann::json result;
        try {
            YAML::Node config = YAML::LoadFile(config_path_);
            auto integ = config["integrations"];

            auto read_integration = [&](const std::string& name) -> nlohmann::json {
                nlohmann::json j;
                if (integ && integ[name]) {
                    auto node = integ[name];
                    j["enabled"]        = node["enabled"]        ? node["enabled"].as<bool>()        : false;
                    j["tenant_id"]      = node["tenant_id"]      ? node["tenant_id"].as<std::string>()      : "";
                    j["client_id"]      = node["client_id"]      ? node["client_id"].as<std::string>()      : "";
                    j["client_secret"]  = node["client_secret"]  ? node["client_secret"].as<std::string>()  : "";
                    j["poll_interval_sec"] = node["poll_interval_sec"] ? node["poll_interval_sec"].as<int>() : 60;
                    // Azure-specific
                    if (node["subscription_id"])
                        j["subscription_id"] = node["subscription_id"].as<std::string>();
                } else {
                    j["enabled"] = false;
                    j["tenant_id"] = "";
                    j["client_id"] = "";
                    j["client_secret"] = "";
                    j["poll_interval_sec"] = 60;
                }
                return j;
            };

            result["m365"]  = read_integration("m365");
            result["azure"] = read_integration("azure");

            // Include live status
            result["m365"]["events_collected"]  = poller_.m365_events();
            result["azure"]["events_collected"] = poller_.azure_events();
            result["poller_running"] = poller_.is_running();

        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
            return;
        }
        res.set_content(result.dump(2), "application/json");
    });

    server_.Post("/api/integrations", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);

            // Load existing YAML
            YAML::Node config = YAML::LoadFile(config_path_);

            // Update integrations section
            auto update_integration = [&](const std::string& name, const nlohmann::json& j) {
                config["integrations"][name]["enabled"]          = j.value("enabled", false);
                config["integrations"][name]["tenant_id"]        = j.value("tenant_id", "");
                config["integrations"][name]["client_id"]        = j.value("client_id", "");
                config["integrations"][name]["client_secret"]    = j.value("client_secret", "");
                config["integrations"][name]["poll_interval_sec"] = j.value("poll_interval_sec", 60);
                if (j.contains("subscription_id")) {
                    config["integrations"][name]["subscription_id"] = j.value("subscription_id", "");
                }
            };

            if (body.contains("m365"))  update_integration("m365", body["m365"]);
            if (body.contains("azure")) update_integration("azure", body["azure"]);

            // Write back to YAML file
            std::ofstream fout(config_path_);
            if (!fout.is_open()) {
                res.status = 500;
                res.set_content(nlohmann::json({{"error", "Cannot write config file"}}).dump(), "application/json");
                return;
            }
            fout << config;
            fout.close();

            // Build new HttpPollerConfig and reconfigure
            HttpPollerConfig new_poller_config;
            if (body.contains("m365")) {
                auto& m = body["m365"];
                new_poller_config.m365_enabled = m.value("enabled", false);
                new_poller_config.m365_oauth.tenant_id     = m.value("tenant_id", "");
                new_poller_config.m365_oauth.client_id     = m.value("client_id", "");
                new_poller_config.m365_oauth.client_secret = m.value("client_secret", "");
                new_poller_config.m365_poll_interval_sec    = m.value("poll_interval_sec", 60);
            }
            if (body.contains("azure")) {
                auto& a = body["azure"];
                new_poller_config.azure_enabled = a.value("enabled", false);
                new_poller_config.azure_oauth.tenant_id     = a.value("tenant_id", "");
                new_poller_config.azure_oauth.client_id     = a.value("client_id", "");
                new_poller_config.azure_oauth.client_secret = a.value("client_secret", "");
                new_poller_config.azure_subscription_id     = a.value("subscription_id", "");
                new_poller_config.azure_poll_interval_sec    = a.value("poll_interval_sec", 60);
            }

            poller_.reconfigure(new_poller_config);

            LOG_INFO("Integration config updated via API");
            res.set_content(nlohmann::json({{"status", "ok"}}).dump(), "application/json");

        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // CORS
    server_.set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        return httplib::Server::HandlerResponse::Unhandled;
    });
    server_.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 204;
    });
}

} // namespace outpost
