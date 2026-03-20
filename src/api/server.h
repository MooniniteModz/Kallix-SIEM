#pragma once

#include "storage/postgres_storage_engine.h"
#include "ingestion/ring_buffer.h"
#include <httplib.h>
#include <thread>
#include <atomic>
#include <cstdint>

namespace outpost {

struct ApiConfig {
    std::string bind_address = "0.0.0.0";
    uint16_t    port         = 8080;
};

/// ────────────────────────────────────────────────────────────────
/// ApiServer: REST API for querying events, viewing stats, and
/// managing the Outpost SIEM. Serves the React frontend in
/// production.
/// ────────────────────────────────────────────────────────────────
class ApiServer {
public:
    ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer,
              const ApiConfig& config = {});
    ~ApiServer();

    void start();
    void stop();

private:
    void setup_routes();

    httplib::Server   server_;
    PostgresStorageEngine&    storage_;
    RingBuffer<>&     buffer_;
    ApiConfig         config_;
    std::thread       thread_;
    std::atomic<bool> running_{false};
};

} // namespace outpost
