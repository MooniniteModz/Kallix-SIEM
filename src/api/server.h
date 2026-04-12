#pragma once

#include "storage/postgres_storage_engine.h"
#include "ingestion/ring_buffer.h"
#include "ingestion/http_poller.h"
#include "ingestion/connector_manager.h"
#include "rules/rule_engine.h"
#include "auth/auth.h"
#include "auth/smtp.h"
#include <httplib.h>
#include <thread>
#include <atomic>
#include <cstdint>

namespace outpost {

struct ApiConfig {
    std::string bind_address  = "0.0.0.0";
    uint16_t    port          = 8080;
    std::string cors_origin   = "*";
    std::string hec_token;    // HEC auth token; if empty, endpoint warns but accepts all
};

class ApiServer {
public:
    ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer,
              HttpPoller& poller, RuleEngine& rule_engine,
              ConnectorManager& connector_mgr,
              const std::string& config_path,
              const AuthConfig& auth_config = {},
              const ApiConfig& config = {},
              const SmtpConfig& smtp_config = {});
    ~ApiServer();

    void start();
    void stop();

    // Helper: extract bearer token and validate session, returns nullopt on failure
    std::optional<PostgresStorageEngine::SessionInfo>
    require_auth(const httplib::Request& req, httplib::Response& res);

    // Helper: require admin role, sends 403 and returns false if not admin
    bool require_admin(const httplib::Request& req, httplib::Response& res);

private:
    void setup_routes();
    void register_auth_routes();
    void register_user_routes();
    void register_stats_routes();
    void register_event_routes();
    void register_alert_routes();
    void register_rule_routes();
    void register_report_routes();
    void register_integration_routes();
    void register_geo_routes();
    void register_connector_routes();
    void register_hec_routes();

    httplib::Server            server_;
    PostgresStorageEngine&     storage_;
    RingBuffer<>&              buffer_;
    HttpPoller&                poller_;
    ConnectorManager&          connector_mgr_;
    RuleEngine&                rule_engine_;
    std::string                config_path_;
    AuthConfig                 auth_config_;
    ApiConfig                  config_;
    SmtpConfig                 smtp_config_;
    std::thread                thread_;
    std::atomic<bool>          running_{false};
};

} // namespace outpost
