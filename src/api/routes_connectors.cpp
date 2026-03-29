// ApiServer — Connector, integration, and geo routes
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/utils.h"
#include "common/logger.h"

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <fstream>

namespace outpost {

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
}

void ApiServer::register_geo_routes() {

    server_.Get("/api/geo/points", [this](const httplib::Request& req, httplib::Response& res) {
        std::string source_filter = req.has_param("source") ? req.get_param_value("source") : "";

        auto points = storage_.get_geo_points(source_filter);

        auto connectors = storage_.get_connectors();
        for (const auto& c : connectors) {
            try {
                auto settings = nlohmann::json::parse(c.settings_json, nullptr, false);
                if (settings.contains("devices") && settings["devices"].is_array()) {
                    for (const auto& dev : settings["devices"]) {
                        if (!dev.contains("latitude") || !dev.contains("longitude")) continue;
                        if (!source_filter.empty() && source_filter != "all" && source_filter != c.type) continue;
                        PostgresStorageEngine::GeoPoint gp;
                        gp.latitude   = dev.value("latitude", 0.0);
                        gp.longitude  = dev.value("longitude", 0.0);
                        gp.label      = dev.value("name", c.name);
                        gp.source     = c.type;
                        gp.point_type = "device";
                        gp.status     = c.status == "running" ? "online" : "offline";
                        gp.count      = 1;
                        nlohmann::json details;
                        details["connector"] = c.name;
                        details["device_type"] = dev.value("type", "unknown");
                        if (dev.contains("ip")) details["ip"] = dev["ip"];
                        if (dev.contains("mac")) details["mac"] = dev["mac"];
                        if (dev.contains("model")) details["model"] = dev["model"];
                        gp.details = details.dump();
                        points.push_back(std::move(gp));
                    }
                }
            } catch (...) {}
        }

        nlohmann::json result = nlohmann::json::array();
        for (const auto& pt : points) {
            result.push_back({
                {"lat", pt.latitude}, {"lng", pt.longitude},
                {"label", pt.label}, {"source", pt.source},
                {"type", pt.point_type}, {"status", pt.status},
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
            connector_mgr_.on_connector_changed(c.id);
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
            connector_mgr_.on_connector_changed(id);
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
        connector_mgr_.on_connector_changed(id);
        res.set_content(R"({"status":"ok"})", "application/json");
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
