#pragma once

#include "ingestion/ring_buffer.h"
#include <atomic>
#include <string>
#include <thread>
#include <chrono>

namespace outpost {

/// OAuth2 client credentials for API access
struct OAuthConfig {
    std::string tenant_id;
    std::string client_id;
    std::string client_secret;
    std::string token_endpoint;  // auto-derived from tenant_id if empty
};

/// Configuration for the HTTP poller
struct HttpPollerConfig {
    // M365 Management Activity API
    bool        m365_enabled = false;
    OAuthConfig m365_oauth;
    int         m365_poll_interval_sec = 60;

    // Azure Monitor / Activity Log API
    bool        azure_enabled = false;
    OAuthConfig azure_oauth;
    std::string azure_subscription_id;
    int         azure_poll_interval_sec = 60;
};

/// ────────────────────────────────────────────────────────────────
/// HttpPoller: periodically fetches logs from M365 and Azure APIs.
///
/// Uses OAuth2 client credentials flow to authenticate, then polls
/// the respective REST APIs for new audit events. Events are pushed
/// into the shared ring buffer as JSON strings for the parser
/// pipeline to process.
///
/// M365: Office 365 Management Activity API
///   - Creates subscriptions for Audit.AzureActiveDirectory,
///     Audit.Exchange, Audit.SharePoint, Audit.General
///   - Polls content blobs and retrieves individual events
///
/// Azure: Azure Monitor Activity Log REST API
///   - Queries activity events with time filter
/// ────────────────────────────────────────────────────────────────
class HttpPoller {
public:
    explicit HttpPoller(RingBuffer<>& buffer, const HttpPollerConfig& config = {});
    ~HttpPoller();

    void start();
    void stop();

    /// Reconfigure and restart with new settings
    void reconfigure(const HttpPollerConfig& new_config);

    /// Get current config (for API readback)
    const HttpPollerConfig& config() const { return config_; }

    bool is_running() const { return running_.load(std::memory_order_relaxed); }

    uint64_t m365_events()  const { return m365_count_.load(std::memory_order_relaxed); }
    uint64_t azure_events() const { return azure_count_.load(std::memory_order_relaxed); }

private:
    /// Obtain an OAuth2 access token
    std::string get_access_token(const OAuthConfig& oauth, const std::string& resource);

    /// M365 polling loop
    void m365_poll_loop();

    /// Azure polling loop
    void azure_poll_loop();

    /// Push a JSON event string into the ring buffer
    void push_event(const std::string& json_event, uint16_t source_port);

    RingBuffer<>&      buffer_;
    HttpPollerConfig   config_;
    std::atomic<bool>  running_{false};

    std::thread m365_thread_;
    std::thread azure_thread_;

    // Cached tokens
    std::string m365_token_;
    std::chrono::steady_clock::time_point m365_token_expiry_;
    std::string azure_token_;
    std::chrono::steady_clock::time_point azure_token_expiry_;

    std::atomic<uint64_t> m365_count_{0};
    std::atomic<uint64_t> azure_count_{0};
};

} // namespace outpost
