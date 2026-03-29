// ApiServer — Health, stats, and reporting routes
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/utils.h"

#include <nlohmann/json.hpp>

namespace outpost {

// Defined in server.cpp
extern int64_t g_start_time;

void ApiServer::register_stats_routes() {

    server_.Get("/api/health", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json health = {
            {"status", "ok"}, {"version", "0.3.0"},
            {"uptime_ms", now_ms() - g_start_time},
            {"buffer_usage", buffer_.size_approx()},
            {"buffer_capacity", buffer_.capacity()},
            {"buffer_drops", buffer_.drop_count()},
            {"events_stored_today", storage_.count_today()},
            {"total_events_inserted", storage_.total_inserted()},
            {"active_rules", rule_engine_.rule_count()},
            {"alerts_fired", rule_engine_.alerts_fired()}
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
            {"uptime_ms", now_ms() - g_start_time}
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
}

void ApiServer::register_report_routes() {

    server_.Get("/api/reports/summary", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json report;

        report["events_today"]    = storage_.count_today();
        report["total_events"]    = storage_.total_inserted();
        report["alert_count"]     = storage_.alert_count();
        report["uptime_ms"]       = now_ms() - g_start_time;
        report["buffer_usage"]    = buffer_.size_approx();
        report["buffer_drops"]    = buffer_.drop_count();
        report["rule_count"]      = rule_engine_.rule_count();
        report["alerts_fired"]    = rule_engine_.alerts_fired();

        report["by_source"]    = storage_.count_by_field("source_type");
        report["by_severity"]  = storage_.count_by_field("severity");
        report["by_category"]  = storage_.count_by_field("category");

        report["top_ips"]      = storage_.top_values("src_ip", 15);
        report["top_users"]    = storage_.top_values("user_name", 15);
        report["top_actions"]  = storage_.top_values("action", 15);

        report["timeline_24h"] = storage_.event_timeline(24);
        report["timeline_7d"]  = storage_.event_timeline(168);

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
}

} // namespace outpost
