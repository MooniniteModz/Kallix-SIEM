// ApiServer — Core lifecycle and middleware
// Route handlers are split into separate files:
//   routes_auth.cpp        — Login, logout, session
//   routes_users.cpp       — User management (admin CRUD)
//   routes_stats.cpp       — Health, stats, timeline, reports
//   routes_events.cpp      — Events query + alerts
//   routes_rules.cpp       — Rule CRUD
//   routes_connectors.cpp  — Connectors, integrations, geo

#include "api/server.h"
#include "common/logger.h"
#include "common/utils.h"

#include <nlohmann/json.hpp>

namespace outpost {

// Shared start time — used by stats/health routes
int64_t g_start_time = 0;

ApiServer::ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer,
                     HttpPoller& poller, RuleEngine& rule_engine,
                     ConnectorManager& connector_mgr,
                     const std::string& config_path,
                     const AuthConfig& auth_config,
                     const ApiConfig& config)
    : storage_(storage), buffer_(buffer), poller_(poller),
      connector_mgr_(connector_mgr),
      rule_engine_(rule_engine), config_path_(config_path),
      auth_config_(auth_config), config_(config) {
    g_start_time = now_ms();
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

// ── Helper: extract Bearer token from request ──
static std::string get_bearer_token(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return "";
    const auto& val = it->second;
    if (val.substr(0, 7) == "Bearer ") return val.substr(7);
    return "";
}

void ApiServer::setup_routes() {

    // ════════════════════════════════════════════════════════════════
    // CORS + AUTH MIDDLEWARE
    // ════════════════════════════════════════════════════════════════

    server_.set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if (req.method == "OPTIONS") return httplib::Server::HandlerResponse::Unhandled;
        if (req.path == "/api/auth/login") return httplib::Server::HandlerResponse::Unhandled;
        if (req.path.substr(0, 4) != "/api") return httplib::Server::HandlerResponse::Unhandled;

        auto token = get_bearer_token(req);
        if (token.empty()) {
            res.status = 401;
            res.set_content(R"({"error":"Authentication required"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }

        auto session = storage_.validate_session(token);
        if (!session) {
            res.status = 401;
            res.set_content(R"({"error":"Invalid or expired session"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    server_.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.status = 204;
    });

    // ── Register route groups ──
    register_auth_routes();
    register_user_routes();
    register_stats_routes();
    register_event_routes();
    register_alert_routes();
    register_rule_routes();
    register_report_routes();
    register_integration_routes();
    register_geo_routes();
    register_connector_routes();
}

} // namespace outpost
