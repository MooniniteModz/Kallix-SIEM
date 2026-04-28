// ApiServer — Rule CRUD routes
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/utils.h"
#include "rules/rule.h"

#include <nlohmann/json.hpp>
#include <filesystem>

namespace outpost {

void ApiServer::register_rule_routes() {

    // Derive rules directory from the config file path (e.g. ./config/outpost.yaml → ./config/rules)
    namespace fs = std::filesystem;
    std::string rules_dir = (fs::path(config_path_).parent_path() / "rules").string();

    server_.Get("/api/rules", [this, rules_dir](const httplib::Request&, httplib::Response& res) {
        auto yaml_rules = load_rules_from_directory(rules_dir);
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

    server_.Post("/api/rules", [this, rules_dir](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
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

            if (body.contains("config")) r.config_json = body["config"].dump();
            else r.config_json = "{}";
            if (body.contains("tags")) r.tags_json = body["tags"].dump();
            else r.tags_json = "[]";

            if (!storage_.save_custom_rule(r)) {
                res.status = 500;
                res.set_content(R"({"error":"Failed to save rule"})", "application/json");
                return;
            }

            rule_engine_.reload_rules(rules_dir);

            nlohmann::json result = {{"id", r.id}, {"status", "created"}};
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Put("/api/rules", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
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

            if (!storage_.update_custom_rule(r)) {
                res.status = 404;
                res.set_content(R"({"error":"Rule not found"})", "application/json");
                return;
            }
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Delete("/api/rules", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
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
}

} // namespace outpost
