#pragma once

#include "ingestion/ring_buffer.h"
#include "storage/postgres_storage_engine.h"
#include "common/logger.h"
#include "common/utils.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace outpost {

/// Result of a connection test
struct TestResult {
    bool   ok = false;
    int    status_code = 0;
    std::string message;
    int    event_count = 0;   // events found in the test response
};

/// A single running REST API poller instance (one per connector)
class ApiPollerInstance {
public:
    ApiPollerInstance(const std::string& connector_id,
                     const nlohmann::json& settings,
                     RingBuffer<>& buffer,
                     PostgresStorageEngine& storage);
    ~ApiPollerInstance();

    void start();
    void stop();
    bool is_running() const { return running_.load(std::memory_order_relaxed); }
    uint64_t event_count() const { return event_count_.load(std::memory_order_relaxed); }

    /// Test the connection without starting the poll loop
    static TestResult test_connection(const nlohmann::json& settings);

private:
    void poll_loop();

    /// Build authentication headers from settings
    static httplib::Headers build_auth_headers(const nlohmann::json& settings);

    /// Get OAuth2 token
    static std::string get_oauth2_token(const nlohmann::json& settings);

    /// Make an authenticated GET request and return parsed JSON
    static std::pair<int, nlohmann::json> authenticated_get(
        const std::string& url,
        const nlohmann::json& settings,
        const std::string& cached_token = "");

    /// Extract events array from API response based on common patterns
    static std::vector<nlohmann::json> extract_events(const nlohmann::json& response);

    /// Parse URL into host and path
    static bool parse_url(const std::string& url, std::string& scheme,
                          std::string& host, std::string& path);

    std::string connector_id_;
    nlohmann::json settings_;
    RingBuffer<>& buffer_;
    PostgresStorageEngine& storage_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> event_count_{0};

    // OAuth2 token cache
    std::string cached_token_;
    std::chrono::steady_clock::time_point token_expiry_;
};

/// Manages all connector polling instances.
/// Reads enabled connectors from the database and starts/stops pollers accordingly.
class ConnectorManager {
public:
    ConnectorManager(RingBuffer<>& buffer, PostgresStorageEngine& storage);
    ~ConnectorManager();

    /// Load enabled connectors from DB and start polling
    void start();

    /// Stop all pollers
    void stop();

    /// Sync state: start new connectors, stop removed/disabled ones
    void sync();

    /// Test a connector's settings (does not require it to be saved)
    TestResult test_connection(const nlohmann::json& settings);

    /// Called by API when a connector is created/updated/deleted/toggled
    void on_connector_changed(const std::string& connector_id);

private:
    void sync_loop();

    RingBuffer<>& buffer_;
    PostgresStorageEngine& storage_;

    std::mutex mu_;
    std::unordered_map<std::string, std::unique_ptr<ApiPollerInstance>> pollers_;

    std::atomic<bool> running_{false};
    std::thread sync_thread_;
};

} // namespace outpost
