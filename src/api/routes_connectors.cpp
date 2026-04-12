// ApiServer — Connector, integration, and geo routes
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/utils.h"
#include "common/logger.h"

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <algorithm>
#include <fstream>

namespace outpost {

// ── Source label resolution ──────────────────────────────────────────────────
// Mirrors the logic in connector_manager.cpp so the API layer produces the same
// source_type strings that end up in the events table.

static std::string resolve_source_label(const std::string& name,
                                        const std::string& url,
                                        const std::string& explicit_label) {
    if (!explicit_label.empty()) return explicit_label;

    auto check = [](const std::string& haystack, const std::string& needle) {
        std::string low = haystack;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        return low.find(needle) != std::string::npos;
    };

    if (check(name, "unifi") || check(name, "ubiquiti"))    return "unifi";
    if (check(name, "azure"))                                return "azure";
    if (check(name, "m365") || check(name, "office") ||
        check(name, "microsoft 365"))                        return "m365";
    if (check(name, "fortigate") || check(name, "fortinet")) return "fortigate";
    if (check(name, "windows"))                              return "windows";
    if (check(name, "sentinel"))                             return "sentinelone";
    if (check(name, "crowdstrike") || check(name, "falcon")) return "crowdstrike";
    if (check(name, "syslog"))                               return "syslog";

    if (!url.empty()) {
        if (check(url, "unifi") || check(url, "ubiquiti"))    return "unifi";
        if (check(url, "azure"))                               return "azure";
        if (check(url, "manage.office"))                       return "m365";
        if (check(url, "fortigate") || check(url, "fortinet")) return "fortigate";
        if (check(url, "sentinel"))                            return "sentinelone";
        if (check(url, "crowdstrike") || check(url, "falcon")) return "crowdstrike";
    }

    return "rest_api";
}

void ApiServer::register_integration_routes() {

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
                    // Mask client_secret — never expose secrets via API
                    std::string secret = node["client_secret"] ? node["client_secret"].as<std::string>() : "";
                    j["client_secret"]  = secret.empty() ? "" : "****";
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
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            YAML::Node config = YAML::LoadFile(config_path_);

            auto update_integration = [&](const std::string& name, const nlohmann::json& j) {
                config["integrations"][name]["enabled"]           = j.value("enabled", false);
                config["integrations"][name]["tenant_id"]         = j.value("tenant_id", "");
                config["integrations"][name]["client_id"]         = j.value("client_id", "");
                // Only write the secret when a real value is provided.
                // The GET endpoint masks the secret as "****" so that it is never
                // exposed via the API. If "****" (or empty) is sent back on save,
                // keep the existing YAML value intact — otherwise every Settings
                // page save would silently corrupt the stored credential.
                std::string new_secret = j.value("client_secret", "");
                if (new_secret != "****" && !new_secret.empty()) {
                    config["integrations"][name]["client_secret"] = new_secret;
                }
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

            // Build the live poller config by reading secrets back from the YAML
            // node (which update_integration just wrote), not from the request body.
            // This ensures "****" placeholders in the request never reach the poller.
            auto yaml_secret = [&](const std::string& name) -> std::string {
                auto node = config["integrations"][name];
                return (node && node["client_secret"]) ? node["client_secret"].as<std::string>() : "";
            };

            HttpPollerConfig new_poller_config;
            if (body.contains("m365")) {
                auto& m = body["m365"];
                new_poller_config.m365_enabled = m.value("enabled", false);
                new_poller_config.m365_oauth.tenant_id     = m.value("tenant_id", "");
                new_poller_config.m365_oauth.client_id     = m.value("client_id", "");
                new_poller_config.m365_oauth.client_secret = yaml_secret("m365");
                new_poller_config.m365_poll_interval_sec    = m.value("poll_interval_sec", 60);
            }
            if (body.contains("azure")) {
                auto& a = body["azure"];
                new_poller_config.azure_enabled = a.value("enabled", false);
                new_poller_config.azure_oauth.tenant_id     = a.value("tenant_id", "");
                new_poller_config.azure_oauth.client_id     = a.value("client_id", "");
                new_poller_config.azure_oauth.client_secret = yaml_secret("azure");
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
}

void ApiServer::register_geo_routes() {

    server_.Get("/api/geo/points", [this](const httplib::Request& req, httplib::Response& res) {
        std::string source_filter = req.has_param("source") ? req.get_param_value("source") : "";
        std::string severity_filter = req.has_param("severity") ? req.get_param_value("severity") : "";

        auto points = storage_.get_geo_points(source_filter, severity_filter);

        // Also include connector device locations (these don't have severity)
        if (severity_filter.empty() || severity_filter == "all") {
            auto connectors = storage_.get_connectors();
            for (const auto& c : connectors) {
                try {
                    auto settings = nlohmann::json::parse(c.settings_json, nullptr, false);
                    if (settings.is_discarded()) continue;

                    // Resolve source label — same logic as connector_manager poll_loop
                    std::string resolved_source = settings.value("source_label", "");
                    if (resolved_source.empty()) {
                        std::string lower_name = c.name;
                        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
                        if (lower_name.find("unifi") != std::string::npos ||
                            lower_name.find("ubiquiti") != std::string::npos)
                            resolved_source = "unifi";
                        else if (lower_name.find("azure") != std::string::npos)
                            resolved_source = "azure";
                        else if (lower_name.find("m365") != std::string::npos ||
                                 lower_name.find("office") != std::string::npos)
                            resolved_source = "m365";
                        else if (lower_name.find("fortigate") != std::string::npos ||
                                 lower_name.find("fortinet") != std::string::npos)
                            resolved_source = "fortigate";
                        else if (lower_name.find("sentinel") != std::string::npos)
                            resolved_source = "sentinelone";
                        else if (lower_name.find("crowdstrike") != std::string::npos ||
                                 lower_name.find("falcon") != std::string::npos)
                            resolved_source = "crowdstrike";
                        else
                            resolved_source = c.type;
                    }

                    if (!source_filter.empty() && source_filter != "all" &&
                        source_filter != resolved_source) continue;

                    std::string conn_status = (c.status == "running") ? "online" : "offline";

                    if (settings.contains("devices") && settings["devices"].is_array()) {
                        // Case 1: explicit per-device lat/lng list
                        for (const auto& dev : settings["devices"]) {
                            if (!dev.contains("latitude") || !dev.contains("longitude")) continue;
                            PostgresStorageEngine::GeoPoint gp;
                            gp.latitude   = dev.value("latitude", 0.0);
                            gp.longitude  = dev.value("longitude", 0.0);
                            gp.label      = dev.value("name", c.name);
                            gp.source     = resolved_source;
                            gp.point_type = "device";
                            gp.status     = conn_status;
                            gp.severity   = "info";
                            gp.count      = 1;
                            nlohmann::json details;
                            details["connector"] = c.name;
                            details["device_type"] = dev.value("type", "unknown");
                            if (dev.contains("ip"))    details["ip"]    = dev["ip"];
                            if (dev.contains("mac"))   details["mac"]   = dev["mac"];
                            if (dev.contains("model")) details["model"] = dev["model"];
                            gp.details = details.dump();
                            points.push_back(std::move(gp));
                        }
                    } else if (settings.contains("latitude") && settings.contains("longitude")) {
                        // Case 2: connector-level location (single point for the whole connector)
                        double lat = 0.0, lng = 0.0;
                        try { lat = settings["latitude"].get<double>(); } catch (...) {}
                        try { lng = settings["longitude"].get<double>(); } catch (...) {}
                        if (lat == 0.0 && lng == 0.0) continue; // skip null island
                        PostgresStorageEngine::GeoPoint gp;
                        gp.latitude   = lat;
                        gp.longitude  = lng;
                        gp.label      = settings.value("location_label", c.name);
                        gp.source     = resolved_source;
                        gp.point_type = "connector";
                        gp.status     = conn_status;
                        gp.severity   = "info";
                        gp.count      = 1;
                        nlohmann::json details;
                        details["connector"] = c.name;
                        gp.details = details.dump();
                        points.push_back(std::move(gp));
                    }
                } catch (...) {}
            }
        }

        nlohmann::json result = nlohmann::json::array();
        for (const auto& pt : points) {
            result.push_back({
                {"lat", pt.latitude}, {"lng", pt.longitude},
                {"label", pt.label}, {"source", pt.source},
                {"type", pt.point_type}, {"status", pt.status},
                {"severity", pt.severity},
                {"count", pt.count},
                {"details", pt.details.empty() ? nlohmann::json(nullptr) :
                            nlohmann::json::parse(pt.details, nullptr, false)}
            });
        }

        res.set_content(nlohmann::json({
            {"count", result.size()},
            {"points", result}
        }).dump(), "application/json");
    });
}

void ApiServer::register_connector_routes() {

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
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            PostgresStorageEngine::ConnectorRecord c;
            c.id      = generate_uuid();
            c.name    = body.value("name", "");
            c.type    = body.value("type", "");
            c.enabled = body.value("enabled", false);
            c.status  = "stopped";
            c.event_count = 0;
            c.created_at  = now_ms();
            c.updated_at  = c.created_at;

            if (c.name.empty() || c.type.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"name and type required"})", "application/json");
                return;
            }

            // Resolve and stamp the source_label into settings so:
            //   (a) connector_manager uses a consistent label, and
            //   (b) the sources endpoint can advertise this connector before any events arrive.
            nlohmann::json settings = body.contains("settings")
                                      ? body["settings"] : nlohmann::json::object();
            std::string explicit_label = settings.value("source_label", "");
            std::string url            = settings.value("url", "");
            std::string resolved       = resolve_source_label(c.name, url, explicit_label);
            settings["source_label"]   = resolved;
            c.settings_json            = settings.dump();

            storage_.save_connector(c);
            connector_mgr_.on_connector_changed(c.id);
            res.set_content(nlohmann::json({
                {"status", "ok"}, {"id", c.id}, {"source_label", resolved}
            }).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Put("/api/connectors", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
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
            connector_mgr_.on_connector_changed(id);
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Delete("/api/connectors", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        std::string id;
        if (req.has_param("id")) id = req.get_param_value("id");
        if (id.empty()) {
            try {
                auto body = nlohmann::json::parse(req.body);
                id = body.value("id", "");
            } catch (...) {}
        }
        if (id.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"id required"})", "application/json");
            return;
        }

        // Resolve the source label so we can cascade-delete its events.
        int64_t events_deleted = 0;
        std::string source_label;
        auto rec = storage_.get_connector(id);
        if (rec) {
            try {
                auto settings  = nlohmann::json::parse(rec->settings_json);
                source_label   = settings.value("source_label", "");
                if (source_label.empty()) {
                    source_label = resolve_source_label(
                        rec->name, settings.value("url", ""), "");
                }
            } catch (...) {}

            if (!source_label.empty()) {
                events_deleted = storage_.delete_events_by_source(source_label);
            }
        }

        storage_.delete_connector(id);
        connector_mgr_.on_connector_changed(id);

        LOG_INFO("Connector '{}' deleted (source: '{}', {} events removed)",
                 id, source_label, events_deleted);
        res.set_content(nlohmann::json({
            {"status", "ok"},
            {"source_label", source_label},
            {"events_deleted", events_deleted}
        }).dump(), "application/json");
    });

    server_.Post("/api/connectors/test", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            auto settings = body.value("settings", nlohmann::json::object());
            auto result = connector_mgr_.test_connection(settings);
            res.set_content(nlohmann::json({
                {"ok", result.ok},
                {"status_code", result.status_code},
                {"message", result.message},
                {"event_count", result.event_count}
            }).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
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
