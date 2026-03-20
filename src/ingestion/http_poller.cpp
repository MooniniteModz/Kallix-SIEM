#include "ingestion/http_poller.h"
#include "common/logger.h"
#include "common/utils.h"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>

namespace outpost {

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
// Stub implementations when SSL is not available
HttpPoller::HttpPoller(RingBuffer<>& buffer, const HttpPollerConfig& config)
    : buffer_(buffer), config_(config) {}
HttpPoller::~HttpPoller() { stop(); }
void HttpPoller::start() {
    if (config_.m365_enabled || config_.azure_enabled) {
        LOG_WARN("HTTP poller: M365/Azure polling requires OpenSSL. Rebuild with -DOPENSSL_FOUND=ON");
    }
}
void HttpPoller::stop() {}
std::string HttpPoller::get_access_token(const OAuthConfig&, const std::string&) { return ""; }
void HttpPoller::m365_poll_loop() {}
void HttpPoller::azure_poll_loop() {}
void HttpPoller::push_event(const std::string&, uint16_t) {}

#else
// Full implementation with SSL support

HttpPoller::HttpPoller(RingBuffer<>& buffer, const HttpPollerConfig& config)
    : buffer_(buffer), config_(config) {}

HttpPoller::~HttpPoller() {
    stop();
}

void HttpPoller::start() {
    if (running_.exchange(true)) return;

    if (config_.m365_enabled) {
        LOG_INFO("M365 poller starting (interval: {}s)", config_.m365_poll_interval_sec);
        m365_thread_ = std::thread(&HttpPoller::m365_poll_loop, this);
    }

    if (config_.azure_enabled) {
        LOG_INFO("Azure poller starting (interval: {}s)", config_.azure_poll_interval_sec);
        azure_thread_ = std::thread(&HttpPoller::azure_poll_loop, this);
    }
}

void HttpPoller::stop() {
    if (!running_.exchange(false)) return;

    if (m365_thread_.joinable()) m365_thread_.join();
    if (azure_thread_.joinable()) azure_thread_.join();

    LOG_INFO("HTTP pollers stopped. M365 events: {}, Azure events: {}",
             m365_count_.load(), azure_count_.load());
}

// ── OAuth2 Client Credentials Flow ──

std::string HttpPoller::get_access_token(const OAuthConfig& oauth, const std::string& resource) {
    std::string endpoint = oauth.token_endpoint;
    if (endpoint.empty()) {
        endpoint = "https://login.microsoftonline.com/" + oauth.tenant_id + "/oauth2/v2.0/token";
    }

    // Parse host and path from endpoint
    std::string host, path;
    {
        // Skip https://
        auto start = endpoint.find("://");
        if (start == std::string::npos) return "";
        start += 3;
        auto slash = endpoint.find('/', start);
        if (slash == std::string::npos) return "";
        host = endpoint.substr(start, slash - start);
        path = endpoint.substr(slash);
    }

    httplib::Client client(host);
    client.set_connection_timeout(10);
    client.set_read_timeout(10);

    std::string body = "grant_type=client_credentials"
                       "&client_id=" + oauth.client_id +
                       "&client_secret=" + oauth.client_secret +
                       "&scope=" + resource;

    auto res = client.Post(path, body, "application/x-www-form-urlencoded");
    if (!res || res->status != 200) {
        LOG_ERROR("OAuth2 token request failed: {}",
                  res ? std::to_string(res->status) : "connection error");
        return "";
    }

    try {
        auto j = nlohmann::json::parse(res->body);
        return j.value("access_token", "");
    } catch (...) {
        LOG_ERROR("Failed to parse OAuth2 token response");
        return "";
    }
}

// ── M365 Management Activity API ──

void HttpPoller::m365_poll_loop() {
    const auto& oauth = config_.m365_oauth;
    const std::string scope = "https://manage.office.com/.default";
    const std::string base_host = "manage.office.com";

    // Content types to subscribe to
    const std::vector<std::string> content_types = {
        "Audit.AzureActiveDirectory",
        "Audit.Exchange",
        "Audit.SharePoint",
        "Audit.General"
    };

    LOG_INFO("M365 poller starting for tenant {}", oauth.tenant_id);

    while (running_.load(std::memory_order_relaxed)) {
        // ── Get/refresh token ──
        auto now = std::chrono::steady_clock::now();
        if (m365_token_.empty() || now >= m365_token_expiry_) {
            m365_token_ = get_access_token(oauth, scope);
            m365_token_expiry_ = now + std::chrono::minutes(55);
            if (m365_token_.empty()) {
                LOG_ERROR("M365: Failed to obtain access token, retrying in 30s");
                for (int i = 0; i < 300 && running_.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            LOG_INFO("M365: Obtained access token");
        }

        httplib::Client client(base_host);
        client.set_connection_timeout(15);
        client.set_read_timeout(30);
        httplib::Headers headers = {
            {"Authorization", "Bearer " + m365_token_}
        };

        // ── Poll each content type ──
        for (const auto& content_type : content_types) {
            if (!running_.load()) break;

            // Construct time window: last poll_interval to now
            auto end_time = std::chrono::system_clock::now();
            auto start_time = end_time - std::chrono::seconds(config_.m365_poll_interval_sec + 10);

            auto format_time = [](std::chrono::system_clock::time_point tp) -> std::string {
                auto t = std::chrono::system_clock::to_time_t(tp);
                std::tm tm{};
                gmtime_r(&t, &tm);
                std::ostringstream ss;
                ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
                return ss.str();
            };

            std::string path = "/api/v1.0/" + oauth.tenant_id +
                               "/activity/feed/subscriptions/content"
                               "?contentType=" + content_type +
                               "&startTime=" + format_time(start_time) +
                               "&endTime=" + format_time(end_time);

            auto res = client.Get(path, headers);
            if (!res || res->status != 200) {
                if (res && res->status == 404) {
                    // Subscription might not exist; try to start it
                    std::string sub_path = "/api/v1.0/" + oauth.tenant_id +
                                           "/activity/feed/subscriptions/start"
                                           "?contentType=" + content_type;
                    client.Post(sub_path, headers, "", "application/json");
                    LOG_INFO("M365: Started subscription for {}", content_type);
                } else {
                    LOG_WARN("M365: Failed to list content for {}: {}",
                             content_type, res ? std::to_string(res->status) : "error");
                }
                continue;
            }

            // Response is a JSON array of content blob URIs
            try {
                auto content_list = nlohmann::json::parse(res->body);
                if (!content_list.is_array()) continue;

                for (const auto& item : content_list) {
                    if (!running_.load()) break;

                    std::string content_uri = item.value("contentUri", "");
                    if (content_uri.empty()) continue;

                    // Fetch the actual audit events from the content URI
                    // The URI is a full URL; parse host and path
                    auto proto_end = content_uri.find("://");
                    if (proto_end == std::string::npos) continue;
                    auto host_start = proto_end + 3;
                    auto path_start = content_uri.find('/', host_start);
                    if (path_start == std::string::npos) continue;

                    std::string blob_host = content_uri.substr(host_start, path_start - host_start);
                    std::string blob_path = content_uri.substr(path_start);

                    httplib::Client blob_client(blob_host);
                    blob_client.set_connection_timeout(10);
                    blob_client.set_read_timeout(30);

                    auto blob_res = blob_client.Get(blob_path, headers);
                    if (!blob_res || blob_res->status != 200) continue;

                    // Response is a JSON array of individual audit events
                    auto events = nlohmann::json::parse(blob_res->body);
                    if (!events.is_array()) continue;

                    for (const auto& evt : events) {
                        push_event(evt.dump(), 443);  // port 443 = HTTP source
                        m365_count_.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            } catch (const std::exception& ex) {
                LOG_WARN("M365: Error processing content for {}: {}", content_type, ex.what());
            }
        }

        // ── Wait for next poll interval ──
        for (int i = 0; i < config_.m365_poll_interval_sec * 10 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// ── Azure Activity Log API ──

void HttpPoller::azure_poll_loop() {
    const auto& oauth = config_.azure_oauth;
    const std::string scope = "https://management.azure.com/.default";
    const std::string base_host = "management.azure.com";

    LOG_INFO("Azure poller starting for subscription {}", config_.azure_subscription_id);

    while (running_.load(std::memory_order_relaxed)) {
        // ── Get/refresh token ──
        auto now = std::chrono::steady_clock::now();
        if (azure_token_.empty() || now >= azure_token_expiry_) {
            azure_token_ = get_access_token(oauth, scope);
            azure_token_expiry_ = now + std::chrono::minutes(55);
            if (azure_token_.empty()) {
                LOG_ERROR("Azure: Failed to obtain access token, retrying in 30s");
                for (int i = 0; i < 300 && running_.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            LOG_INFO("Azure: Obtained access token");
        }

        httplib::Client client(base_host);
        client.set_connection_timeout(15);
        client.set_read_timeout(30);
        httplib::Headers headers = {
            {"Authorization", "Bearer " + azure_token_}
        };

        // Time window
        auto end_time = std::chrono::system_clock::now();
        auto start_time = end_time - std::chrono::seconds(config_.azure_poll_interval_sec + 10);

        auto format_time = [](std::chrono::system_clock::time_point tp) -> std::string {
            auto t = std::chrono::system_clock::to_time_t(tp);
            std::tm tm{};
            gmtime_r(&t, &tm);
            std::ostringstream ss;
            ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
            return ss.str();
        };

        // Activity Log REST API
        std::string filter = "$filter=eventTimestamp ge '" + format_time(start_time) +
                             "' and eventTimestamp le '" + format_time(end_time) + "'";
        std::string path = "/subscriptions/" + config_.azure_subscription_id +
                           "/providers/microsoft.insights/eventtypes/management/values"
                           "?api-version=2015-04-01&" + filter;

        auto res = client.Get(path, headers);
        if (!res || res->status != 200) {
            LOG_WARN("Azure: Activity log query failed: {}",
                     res ? std::to_string(res->status) : "connection error");
        } else {
            try {
                auto body = nlohmann::json::parse(res->body);
                auto& values = body["value"];
                if (values.is_array()) {
                    for (const auto& evt : values) {
                        push_event(evt.dump(), 443);
                        azure_count_.fetch_add(1, std::memory_order_relaxed);
                    }

                    if (!values.empty()) {
                        LOG_DEBUG("Azure: Retrieved {} activity events", values.size());
                    }
                }
            } catch (const std::exception& ex) {
                LOG_WARN("Azure: Error parsing activity log: {}", ex.what());
            }
        }

        // ── Wait for next poll interval ──
        for (int i = 0; i < config_.azure_poll_interval_sec * 10 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void HttpPoller::push_event(const std::string& json_event, uint16_t source_port) {
    if (json_event.size() >= RawMessage::MAX_SIZE) {
        LOG_WARN("HTTP poller: event too large ({} bytes), truncating", json_event.size());
    }

    RawMessage msg;
    msg.set(json_event.c_str(), json_event.size(), source_port, "api.microsoft.com");

    if (!buffer_.try_push(msg)) {
        buffer_.record_drop();
    }
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

} // namespace outpost
