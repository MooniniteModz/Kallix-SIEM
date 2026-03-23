#include "api/server.h"
#include "common/event.h"
#include "common/logger.h"
#include "common/utils.h"
#include "rules/rule.h"
#include "auth/auth.h"

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <set>

namespace outpost {

static int64_t s_start_time = 0;

ApiServer::ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer,
                     HttpPoller& poller, RuleEngine& rule_engine,
                     const std::string& config_path,
                     const AuthConfig& auth_config,
                     const ApiConfig& config)
    : storage_(storage), buffer_(buffer), poller_(poller),
      rule_engine_(rule_engine), config_path_(config_path),
      auth_config_(auth_config), config_(config) {
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
        // CORS headers on every response
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

        // Skip auth for OPTIONS (preflight)
        if (req.method == "OPTIONS") return httplib::Server::HandlerResponse::Unhandled;

        // Skip auth for login endpoint
        if (req.path == "/api/auth/login") return httplib::Server::HandlerResponse::Unhandled;

        // Skip auth for non-API paths (frontend static files)
        if (req.path.substr(0, 4) != "/api") return httplib::Server::HandlerResponse::Unhandled;

        // Check Bearer token
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

    // ════════════════════════════════════════════════════════════════
    // AUTH ENDPOINTS
    // ════════════════════════════════════════════════════════════════

    server_.Post("/api/auth/login", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string username = body.value("username", "");
            std::string password = body.value("password", "");

            if (username.empty() || password.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Username and password required"})", "application/json");
                return;
            }

            auto user = storage_.get_user_by_username(username);
            if (!user || !verify_password(password, user->salt, user->password_hash)) {
                res.status = 401;
                res.set_content(R"({"error":"Invalid username or password"})", "application/json");
                return;
            }

            // Create session
            auto token = generate_session_token();
            int64_t now = now_ms();
            int64_t expires = now + (static_cast<int64_t>(auth_config_.session_ttl_hours) * 3600 * 1000);
            storage_.create_session(token, user->user_id, now, expires);

            nlohmann::json result = {
                {"token", token},
                {"expires_at", expires},
                {"username", username},
                {"email", user->email},
                {"role", user->role}
            };
            res.set_content(result.dump(), "application/json");

        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Post("/api/auth/logout", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = get_bearer_token(req);
        if (!token.empty()) storage_.delete_session(token);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server_.Get("/api/auth/me", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = get_bearer_token(req);
        auto session = storage_.validate_session(token);
        if (!session) {
            res.status = 401;
            res.set_content(R"({"error":"Not authenticated"})", "application/json");
            return;
        }
        nlohmann::json result = {
            {"username", session->username},
            {"email", session->email},
            {"role", session->role},
            {"user_id", session->user_id}
        };
        res.set_content(result.dump(), "application/json");
    });

    // ════════════════════════════════════════════════════════════════
    // USER MANAGEMENT (admin-only)
    // ════════════════════════════════════════════════════════════════

    server_.Get("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = get_bearer_token(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
        auto users = storage_.list_users();
        nlohmann::json arr = nlohmann::json::array();
        for (auto& u : users) {
            arr.push_back({
                {"user_id", u.user_id}, {"username", u.username},
                {"email", u.email}, {"role", u.role}, {"created_at", u.created_at}
            });
        }
        res.set_content(arr.dump(), "application/json");
    });

    server_.Post("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = get_bearer_token(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string username = body.value("username", "");
            std::string email    = body.value("email", "");
            std::string password = body.value("password", "");
            std::string role     = body.value("role", "analyst");

            if (username.empty() || password.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Username and password required"})", "application/json");
                return;
            }
            if (password.size() < 4) {
                res.status = 400;
                res.set_content(R"({"error":"Password must be at least 4 characters"})", "application/json");
                return;
            }
            if (storage_.get_user_by_username(username)) {
                res.status = 409;
                res.set_content(R"({"error":"Username already exists"})", "application/json");
                return;
            }
            if (!email.empty() && storage_.get_user_by_email(email)) {
                res.status = 409;
                res.set_content(R"({"error":"Email already in use"})", "application/json");
                return;
            }

            auto salt = generate_salt();
            auto hash = hash_password(password, salt);
            auto uid  = generate_uuid();
            if (!storage_.create_user(uid, username, email, hash, salt, role)) {
                res.status = 500;
                res.set_content(R"({"error":"Failed to create user"})", "application/json");
                return;
            }
            nlohmann::json result = {{"user_id", uid}, {"username", username}, {"email", email}, {"role", role}};
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Put("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = get_bearer_token(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string email   = body.value("email", "");
            std::string role    = body.value("role", "");
            std::string password = body.value("password", "");

            if (user_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"user_id required"})", "application/json");
                return;
            }

            if (!role.empty()) {
                storage_.update_user(user_id, email, role);
            }
            if (!password.empty()) {
                if (password.size() < 4) {
                    res.status = 400;
                    res.set_content(R"({"error":"Password must be at least 4 characters"})", "application/json");
                    return;
                }
                auto salt = generate_salt();
                auto hash = hash_password(password, salt);
                storage_.update_user_password(user_id, hash, salt);
            }
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Delete("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = get_bearer_token(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
        std::string user_id = req.has_param("id") ? req.get_param_value("id") : "";
        if (user_id.empty()) {
            try {
                auto body = nlohmann::json::parse(req.body);
                user_id = body.value("user_id", "");
            } catch (...) {}
        }
        if (user_id.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"user_id required"})", "application/json");
            return;
        }
        if (user_id == session->user_id) {
            res.status = 400;
            res.set_content(R"({"error":"Cannot delete your own account"})", "application/json");
            return;
        }
        storage_.delete_user(user_id);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    // ════════════════════════════════════════════════════════════════
    // HEALTH & STATS
    // ════════════════════════════════════════════════════════════════

    server_.Get("/api/health", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json health = {
            {"status", "ok"}, {"version", "0.3.0"},
            {"uptime_ms", now_ms() - s_start_time},
            {"buffer_usage", buffer_.size_approx()},
            {"buffer_capacity", buffer_.capacity()},
            {"buffer_drops", buffer_.drop_count()},
            {"events_stored_today", storage_.count_today()},
            {"total_events_inserted", storage_.total_inserted()}
        };
        res.set_content(health.dump(2), "application/json");
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

    // ════════════════════════════════════════════════════════════════
    // EVENTS (enhanced with column filters)
    // ════════════════════════════════════════════════════════════════

    server_.Get("/api/events", [this](const httplib::Request& req, httplib::Response& res) {
        int64_t start_ms = 0, end_ms = now_ms();
        std::string keyword; int limit = 100, offset = 0;
        if (req.has_param("start"))  start_ms = std::stoll(req.get_param_value("start"));
        if (req.has_param("end"))    end_ms   = std::stoll(req.get_param_value("end"));
        if (req.has_param("q"))      keyword  = req.get_param_value("q");
        if (req.has_param("limit"))  limit    = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset   = std::stoi(req.get_param_value("offset"));

        // Column filters
        static const std::set<std::string> filter_fields = {
            "source_type", "severity", "category", "action", "src_ip", "user_name", "outcome"
        };
        std::map<std::string, std::string> filters;
        for (const auto& f : filter_fields) {
            if (req.has_param(f)) filters[f] = req.get_param_value(f);
        }

        auto events = storage_.query(start_ms, end_ms, keyword, limit, offset);

        // Apply column filters in-memory (simpler than building dynamic SQL)
        std::vector<nlohmann::json> filtered;
        for (const auto& e : events) {
            auto j = event_to_json(e);
            bool match = true;
            for (const auto& [field, value] : filters) {
                if (j.contains(field) && j[field].is_string() && j[field].get<std::string>() != value) {
                    match = false;
                    break;
                }
            }
            if (match) filtered.push_back(std::move(j));
        }

        res.set_content(nlohmann::json({
            {"count", filtered.size()},
            {"total", storage_.count_today()},
            {"events", filtered}
        }).dump(), "application/json");
    });

    // ════════════════════════════════════════════════════════════════
    // ALERTS (enhanced with acknowledge/close)
    // ════════════════════════════════════════════════════════════════

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

    server_.Post("/api/alerts/acknowledge", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string alert_id = body.value("alert_id", "");
            if (alert_id.empty()) { res.status = 400; res.set_content(R"({"error":"alert_id required"})", "application/json"); return; }
            storage_.update_alert_status(alert_id, "acknowledged");
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Post("/api/alerts/close", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string alert_id = body.value("alert_id", "");
            if (alert_id.empty()) { res.status = 400; res.set_content(R"({"error":"alert_id required"})", "application/json"); return; }
            storage_.update_alert_status(alert_id, "closed");
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ════════════════════════════════════════════════════════════════
    // RULES
    // ════════════════════════════════════════════════════════════════

    server_.Get("/api/rules", [this](const httplib::Request&, httplib::Response& res) {
        // Merge YAML-based rules and custom DB rules
        auto yaml_rules = load_rules_from_directory("./config/rules");
        nlohmann::json result = nlohmann::json::array();
        for (const auto& r : yaml_rules) {
            nlohmann::json j = {
                {"id", r.id}, {"name", r.name}, {"description", r.description},
                {"severity", to_string(r.severity)}, {"enabled", r.enabled},
                {"tags", r.tags}, {"source", "builtin"}
            };
            switch (r.type) {
                case RuleType::Threshold: j["type"] = "threshold"; break;
                case RuleType::Sequence:  j["type"] = "sequence"; break;
                case RuleType::ValueList: j["type"] = "valuelist"; break;
                case RuleType::Anomaly:   j["type"] = "anomaly"; break;
            }
            j["filter"] = {
                {"source_type", r.filter.source_type},
                {"category", r.filter.category},
                {"action", r.filter.action}
            };
            result.push_back(j);
        }
        // Add custom rules from DB
        auto custom = storage_.get_custom_rules();
        for (const auto& c : custom) {
            nlohmann::json j = {
                {"id", c.id}, {"name", c.name}, {"description", c.description},
                {"severity", c.severity}, {"type", c.type}, {"enabled", c.enabled},
                {"source", "custom"}, {"created_at", c.created_at}, {"updated_at", c.updated_at}
            };
            try { j["tags"] = nlohmann::json::parse(c.tags_json); } catch (...) { j["tags"] = nlohmann::json::array(); }
            try { j["config"] = nlohmann::json::parse(c.config_json); } catch (...) { j["config"] = nlohmann::json::object(); }
            j["filter"] = {
                {"source_type", c.source_type}, {"category", c.category}, {"action", c.action},
                {"field_match", c.field_match}, {"field_value", c.field_value}
            };
            result.push_back(j);
        }
        res.set_content(nlohmann::json({{"count", result.size()}, {"rules", result}}).dump(), "application/json");
    });

    server_.Post("/api/rules", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            PostgresStorageEngine::CustomRuleRecord r;
            r.id          = "CUSTOM-" + generate_uuid().substr(0, 8);
            r.name        = body.value("name", "");
            r.description = body.value("description", "");
            r.severity    = body.value("severity", "medium");
            r.type        = body.value("type", "threshold");
            r.source_type = body.value("source_type", "");
            r.category    = body.value("category", "");
            r.action      = body.value("action", "");
            r.field_match = body.value("field_match", "");
            r.field_value = body.value("field_value", "");
            r.enabled     = body.value("enabled", true);
            r.created_at  = now_ms();
            r.updated_at  = now_ms();

            if (r.name.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Rule name is required"})", "application/json");
                return;
            }

            // Config and tags as JSON strings
            if (body.contains("config")) r.config_json = body["config"].dump();
            else r.config_json = "{}";
            if (body.contains("tags")) r.tags_json = body["tags"].dump();
            else r.tags_json = "[]";

            if (!storage_.save_custom_rule(r)) {
                res.status = 500;
                res.set_content(R"({"error":"Failed to save rule"})", "application/json");
                return;
            }

            // Reload rules in engine
            rule_engine_.reload_rules("./config/rules");

            nlohmann::json result = {{"id", r.id}, {"status", "created"}};
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Put("/api/rules", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            PostgresStorageEngine::CustomRuleRecord r;
            r.id          = body.value("id", "");
            r.name        = body.value("name", "");
            r.description = body.value("description", "");
            r.severity    = body.value("severity", "medium");
            r.type        = body.value("type", "threshold");
            r.source_type = body.value("source_type", "");
            r.category    = body.value("category", "");
            r.action      = body.value("action", "");
            r.field_match = body.value("field_match", "");
            r.field_value = body.value("field_value", "");
            r.enabled     = body.value("enabled", true);
            r.updated_at  = now_ms();

            if (r.id.empty() || r.name.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Rule id and name required"})", "application/json");
                return;
            }

            if (body.contains("config")) r.config_json = body["config"].dump();
            else r.config_json = "{}";
            if (body.contains("tags")) r.tags_json = body["tags"].dump();
            else r.tags_json = "[]";

            storage_.update_custom_rule(r);
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Delete("/api/rules", [this](const httplib::Request& req, httplib::Response& res) {
        std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty()) {
            try {
                auto body = nlohmann::json::parse(req.body);
                id = body.value("id", "");
            } catch (...) {}
        }
        if (id.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"Rule id required"})", "application/json");
            return;
        }
        storage_.delete_custom_rule(id);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    // ════════════════════════════════════════════════════════════════
    // REPORTING STATS
    // ════════════════════════════════════════════════════════════════

    server_.Get("/api/reports/summary", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json report;

        // KPIs
        report["events_today"]    = storage_.count_today();
        report["total_events"]    = storage_.total_inserted();
        report["alert_count"]     = storage_.alert_count();
        report["uptime_ms"]       = now_ms() - s_start_time;
        report["buffer_usage"]    = buffer_.size_approx();
        report["buffer_drops"]    = buffer_.drop_count();
        report["rule_count"]      = rule_engine_.rule_count();
        report["alerts_fired"]    = rule_engine_.alerts_fired();

        // Distributions
        report["by_source"]    = storage_.count_by_field("source_type");
        report["by_severity"]  = storage_.count_by_field("severity");
        report["by_category"]  = storage_.count_by_field("category");

        // Top entities
        report["top_ips"]      = storage_.top_values("src_ip", 15);
        report["top_users"]    = storage_.top_values("user_name", 15);
        report["top_actions"]  = storage_.top_values("action", 15);

        // Timelines
        report["timeline_24h"] = storage_.event_timeline(24);
        report["timeline_7d"]  = storage_.event_timeline(168);

        // Recent alerts
        auto alerts = storage_.get_alerts(20);
        nlohmann::json alert_arr = nlohmann::json::array();
        for (const auto& a : alerts) {
            alert_arr.push_back({
                {"alert_id", a.alert_id}, {"rule_name", a.rule_name},
                {"severity", to_string(a.severity)}, {"description", a.description},
                {"group_key", a.group_key}, {"created_at", a.created_at},
                {"event_count", a.event_ids.size()}
            });
        }
        report["recent_alerts"] = alert_arr;

        res.set_content(report.dump(), "application/json");
    });

    // ════════════════════════════════════════════════════════════════
    // INTEGRATION CONFIG (existing endpoints preserved)
    // ════════════════════════════════════════════════════════════════

    server_.Get("/api/integrations", [this](const httplib::Request&, httplib::Response& res) {
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
                    if (node["subscription_id"])
                        j["subscription_id"] = node["subscription_id"].as<std::string>();
                } else {
                    j["enabled"] = false; j["tenant_id"] = ""; j["client_id"] = "";
                    j["client_secret"] = ""; j["poll_interval_sec"] = 60;
                }
                return j;
            };

            result["m365"]  = read_integration("m365");
            result["azure"] = read_integration("azure");
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
            YAML::Node config = YAML::LoadFile(config_path_);

            auto update_integration = [&](const std::string& name, const nlohmann::json& j) {
                config["integrations"][name]["enabled"]          = j.value("enabled", false);
                config["integrations"][name]["tenant_id"]        = j.value("tenant_id", "");
                config["integrations"][name]["client_id"]        = j.value("client_id", "");
                config["integrations"][name]["client_secret"]    = j.value("client_secret", "");
                config["integrations"][name]["poll_interval_sec"] = j.value("poll_interval_sec", 60);
                if (j.contains("subscription_id"))
                    config["integrations"][name]["subscription_id"] = j.value("subscription_id", "");
            };

            if (body.contains("m365"))  update_integration("m365", body["m365"]);
            if (body.contains("azure")) update_integration("azure", body["azure"]);

            std::ofstream fout(config_path_);
            if (!fout.is_open()) {
                res.status = 500;
                res.set_content(R"({"error":"Cannot write config file"})", "application/json");
                return;
            }
            fout << config;
            fout.close();

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
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ════════════════════════════════════════════════════════════════
    // CONNECTORS CRUD
    // ════════════════════════════════════════════════════════════════

    server_.Get("/api/connectors", [this](const httplib::Request&, httplib::Response& res) {
        auto connectors = storage_.get_connectors();
        nlohmann::json result = nlohmann::json::array();
        for (const auto& c : connectors) {
            result.push_back({
                {"id", c.id}, {"name", c.name}, {"type", c.type},
                {"enabled", c.enabled}, {"status", c.status},
                {"event_count", c.event_count},
                {"settings", nlohmann::json::parse(c.settings_json, nullptr, false)},
                {"created_at", c.created_at}, {"updated_at", c.updated_at}
            });
        }
        res.set_content(nlohmann::json({{"count", connectors.size()}, {"connectors", result}}).dump(), "application/json");
    });

    server_.Post("/api/connectors", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            PostgresStorageEngine::ConnectorRecord c;
            c.id            = generate_uuid();
            c.name          = body.value("name", "");
            c.type          = body.value("type", "");
            c.enabled       = body.value("enabled", false);
            c.settings_json = body.contains("settings") ? body["settings"].dump() : "{}";
            c.status        = "stopped";
            c.event_count   = 0;
            c.created_at    = now_ms();
            c.updated_at    = c.created_at;

            if (c.name.empty() || c.type.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"name and type required"})", "application/json");
                return;
            }

            storage_.save_connector(c);
            res.set_content(nlohmann::json({{"status", "ok"}, {"id", c.id}}).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Put("/api/connectors", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string id = body.value("id", "");
            if (id.empty()) { res.status = 400; res.set_content(R"({"error":"id required"})", "application/json"); return; }

            auto existing = storage_.get_connector(id);
            if (!existing) { res.status = 404; res.set_content(R"({"error":"not found"})", "application/json"); return; }

            PostgresStorageEngine::ConnectorRecord c = *existing;
            if (body.contains("name"))     c.name          = body["name"];
            if (body.contains("type"))     c.type          = body["type"];
            if (body.contains("enabled"))  c.enabled       = body["enabled"];
            if (body.contains("settings")) c.settings_json = body["settings"].dump();
            if (body.contains("status"))   c.status        = body["status"];
            c.updated_at = now_ms();

            storage_.update_connector(c);
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Delete("/api/connectors", [this](const httplib::Request& req, httplib::Response& res) {
        std::string id;
        if (req.has_param("id")) id = req.get_param_value("id");
        if (id.empty()) {
            try {
                auto body = nlohmann::json::parse(req.body);
                id = body.value("id", "");
            } catch (...) {}
        }
        if (id.empty()) { res.status = 400; res.set_content(R"({"error":"id required"})", "application/json"); return; }
        storage_.delete_connector(id);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server_.Get("/api/connectors/types", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json types = nlohmann::json::array();
        types.push_back({{"id", "syslog"},   {"name", "Syslog"},    {"description", "Receive syslog messages via UDP/TCP"}, {"icon", "terminal"}});
        types.push_back({{"id", "rest_api"}, {"name", "REST API"},  {"description", "Poll a REST API endpoint with OAuth2, API Key, or Basic auth"}, {"icon", "cloud"}});
        types.push_back({{"id", "webhook"},  {"name", "Webhook"},   {"description", "Receive events via HTTP webhook"}, {"icon", "webhook"}});
        types.push_back({{"id", "file_log"}, {"name", "File / Log"},{"description", "Tail a log file on disk"}, {"icon", "file"}});
        types.push_back({{"id", "kafka"},    {"name", "Kafka"},     {"description", "Consume events from an Apache Kafka topic"}, {"icon", "database"}});
        res.set_content(nlohmann::json({{"types", types}}).dump(), "application/json");
    });
}

} // namespace outpost
