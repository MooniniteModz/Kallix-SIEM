// ApiServer — Event and alert routes
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/event.h"
#include "common/utils.h"

#include <nlohmann/json.hpp>
#include <set>

namespace outpost {

void ApiServer::register_event_routes() {

    server_.Get("/api/events", [this](const httplib::Request& req, httplib::Response& res) {
        int64_t start_ms = 0, end_ms = now_ms();
        std::string keyword; int limit = 100, offset = 0;
        if (req.has_param("start"))  start_ms = std::stoll(req.get_param_value("start"));
        if (req.has_param("end"))    end_ms   = std::stoll(req.get_param_value("end"));
        if (req.has_param("q"))      keyword  = req.get_param_value("q");
        if (req.has_param("limit"))  limit    = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset   = std::stoi(req.get_param_value("offset"));

        static const std::set<std::string> filter_fields = {
            "source_type", "severity", "category", "action", "src_ip", "user_name", "outcome"
        };
        std::map<std::string, std::string> filters;
        for (const auto& f : filter_fields) {
            if (req.has_param(f)) filters[f] = req.get_param_value(f);
        }

        auto events = storage_.query(start_ms, end_ms, keyword, limit, offset);

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
}

void ApiServer::register_alert_routes() {

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
}

} // namespace outpost
