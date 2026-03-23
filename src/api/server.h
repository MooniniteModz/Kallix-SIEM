#pragma once

#include "storage/postgres_storage_engine.h"
#include "ingestion/ring_buffer.h"
#include "ingestion/http_poller.h"
#include "rules/rule_engine.h"
#include "auth/auth.h"
#include <httplib.h>
#include <thread>
#include <atomic>
#include <cstdint>

namespace outpost {

struct ApiConfig {
    std::string bind_address = "0.0.0.0";
    uint16_t    port         = 8080;
};

class ApiServer {
public:
    ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer,
              HttpPoller& poller, RuleEngine& rule_engine,
              const std::string& config_path,
              const AuthConfig& auth_config = {},
              const ApiConfig& config = {});
    ~ApiServer();

    void start();
    void stop();

private:
    void setup_routes();

    httplib::Server            server_;
    PostgresStorageEngine&     storage_;
    RingBuffer<>&              buffer_;
    HttpPoller&                poller_;
    RuleEngine&                rule_engine_;
    std::string                config_path_;
    AuthConfig                 auth_config_;
    ApiConfig                  config_;
    std::thread                thread_;
    std::atomic<bool>          running_{false};
};

} // namespace outpost
