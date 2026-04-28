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
#include <sstream>

namespace outpost {

// Shared start time — used by stats/health routes
int64_t g_start_time = 0;

ApiServer::ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer,
                     HttpPoller& poller, RuleEngine& rule_engine,
                     ConnectorManager& connector_mgr,
                     const std::string& config_path,
                     const AuthConfig& auth_config,
                     const ApiConfig& config,
                     const SmtpConfig& smtp_config)
    : storage_(storage), buffer_(buffer), poller_(poller),
      connector_mgr_(connector_mgr),
      rule_engine_(rule_engine), config_path_(config_path),
      auth_config_(auth_config), config_(config), smtp_config_(smtp_config) {
    g_start_time = now_ms();
}

ApiServer::~ApiServer() { stop(); }

void ApiServer::start() {
    if (running_.exchange(true)) return;
    setup_routes();

    // Request body size limit (8 MB)
    server_.set_payload_max_length(8 * 1024 * 1024);

    thread_ = std::thread([this]() {
        LOG_INFO("API server starting on {}:{}", config_.bind_address, config_.port);
    if (config_.cors_origin == "*" || config_.cors_origin.empty()) {
        LOG_WARN("CORS is set to wildcard '*' — set OUTPOST_CORS_ORIGIN to your frontend URL in production");
    }
        server_.listen(config_.bind_address, config_.port);
    });
}

void ApiServer::stop() {
    if (!running_.exchange(false)) return;
    server_.stop();
    if (thread_.joinable()) thread_.join();
    LOG_INFO("API server stopped");
}

std::optional<PostgresStorageEngine::SessionInfo>
ApiServer::require_auth(const httplib::Request& req, httplib::Response& res) {
    auto token = extract_session_token(req);
    auto session = storage_.validate_session(token);
    if (!session) {
        res.status = 401;
        res.set_content(R"({"error":"Authentication required"})", "application/json");
    }
    return session;
}

bool ApiServer::require_admin(const httplib::Request& req, httplib::Response& res) {
    auto session = require_auth(req, res);
    if (!session) return false;
    if (session->role != "admin") {
        res.status = 403;
        res.set_content(R"({"error":"Admin access required"})", "application/json");
        return false;
    }
    return true;
}

void ApiServer::setup_routes() {

    const std::string cors_origin = config_.cors_origin;

    // ════════════════════════════════════════════════════════════════
    // CORS + AUTH MIDDLEWARE
    // ════════════════════════════════════════════════════════════════

    server_.set_pre_routing_handler([this, cors_origin](const httplib::Request& req, httplib::Response& res) {
        // ── Security headers ──────────────────────────────────────────
        res.set_header("X-Content-Type-Options",  "nosniff");
        res.set_header("X-Frame-Options",          "DENY");
        res.set_header("X-XSS-Protection",         "1; mode=block");
        res.set_header("Referrer-Policy",          "strict-origin-when-cross-origin");
        res.set_header("Content-Security-Policy", "frame-ancestors 'none'");
        res.set_header("Permissions-Policy",       "geolocation=(), camera=(), microphone=()");

        // ── CORS ─────────────────────────────────────────────────────
        if (!cors_origin.empty() && cors_origin != "*") {
            const auto& origin = req.get_header_value("Origin");
            if (!origin.empty() && origin == cors_origin) {
                res.set_header("Access-Control-Allow-Origin",      cors_origin);
                res.set_header("Access-Control-Allow-Credentials", "true");
                res.set_header("Vary", "Origin");
            }
        } else if (cors_origin == "*") {
            // Wildcard only used in dev; warn in logs at startup
            res.set_header("Access-Control-Allow-Origin", "*");
        }
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if (req.method == "OPTIONS") return httplib::Server::HandlerResponse::Unhandled;
        if (req.path == "/api/auth/login")           return httplib::Server::HandlerResponse::Unhandled;
        if (req.path == "/api/auth/forgot-password") return httplib::Server::HandlerResponse::Unhandled;
        if (req.path == "/api/auth/reset-password")  return httplib::Server::HandlerResponse::Unhandled;
        // HEC uses its own token auth — exempt from session auth middleware
        if (req.path.substr(0, 8) == "/api/hec")        return httplib::Server::HandlerResponse::Unhandled;
        if (req.path.substr(0, 9) == "/services")       return httplib::Server::HandlerResponse::Unhandled;
        if (req.path.substr(0, 4) != "/api") return httplib::Server::HandlerResponse::Unhandled;

        auto token = get_session_token(req);
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

    server_.Options(".*", [cors_origin](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", cors_origin);
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
    register_hec_routes();
}

} // namespace outpost
