#include "ingestion/connector_manager.h"

#include <algorithm>
#include <sstream>
#include <iomanip>

namespace outpost {

// ════════════════════════════════════════════════════════════════
// URL PARSING
// ════════════════════════════════════════════════════════════════

bool ApiPollerInstance::parse_url(const std::string& url,
                                  std::string& scheme,
                                  std::string& host,
                                  std::string& path) {
    auto proto_end = url.find("://");
    if (proto_end == std::string::npos) return false;
    scheme = url.substr(0, proto_end);
    auto host_start = proto_end + 3;
    auto path_start = url.find('/', host_start);
    if (path_start == std::string::npos) {
        host = url.substr(host_start);
        path = "/";
    } else {
        host = url.substr(host_start, path_start - host_start);
        path = url.substr(path_start);
    }
    return true;
}

// ════════════════════════════════════════════════════════════════
// AUTH HELPERS
// ════════════════════════════════════════════════════════════════

httplib::Headers ApiPollerInstance::build_auth_headers(const nlohmann::json& settings) {
    httplib::Headers headers;
    std::string auth_type = settings.value("auth_type", "none");

    if (auth_type == "apikey") {
        std::string key = settings.value("api_key", "");
        std::string header_name = settings.value("api_key_header", "X-API-Key");
        if (!key.empty()) {
            headers.emplace(header_name, key);
        }
    } else if (auth_type == "basic") {
        std::string user = settings.value("username", "");
        std::string pass = settings.value("password", "");
        // Base64 encode user:pass
        std::string cred = user + ":" + pass;
        // Simple base64 encoding
        static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        int val = 0, valb = -6;
        for (unsigned char c : cred) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                encoded.push_back(b64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) encoded.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (encoded.size() % 4) encoded.push_back('=');
        headers.emplace("Authorization", "Basic " + encoded);
    } else if (auth_type == "bearer") {
        std::string token = settings.value("bearer_token", "");
        if (!token.empty()) {
            headers.emplace("Authorization", "Bearer " + token);
        }
    }
    // oauth2 is handled separately via get_oauth2_token()
    return headers;
}

std::string ApiPollerInstance::get_oauth2_token(const nlohmann::json& settings) {
    std::string tenant_id = settings.value("tenant_id", "");
    std::string client_id = settings.value("client_id", "");
    std::string client_secret = settings.value("client_secret", "");
    std::string token_url = settings.value("token_url", "");
    std::string scope = settings.value("scope", "");

    if (token_url.empty() && !tenant_id.empty()) {
        // Default to Microsoft identity endpoint
        token_url = "https://login.microsoftonline.com/" + tenant_id + "/oauth2/v2.0/token";
    }

    if (token_url.empty() || client_id.empty() || client_secret.empty()) {
        return "";
    }

    std::string scheme, host, path;
    if (!parse_url(token_url, scheme, host, path)) return "";

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    std::unique_ptr<httplib::Client> client;
    if (scheme == "https") {
        client = std::make_unique<httplib::Client>(std::string("https://") + host);
    } else {
        client = std::make_unique<httplib::Client>(host);
    }
#else
    auto client = std::make_unique<httplib::Client>(host);
#endif

    client->set_connection_timeout(10);
    client->set_read_timeout(10);

    std::string body = "grant_type=client_credentials"
                       "&client_id=" + client_id +
                       "&client_secret=" + client_secret;
    if (!scope.empty()) {
        body += "&scope=" + scope;
    }

    auto res = client->Post(path, body, "application/x-www-form-urlencoded");
    if (!res || res->status != 200) {
        LOG_ERROR("ConnectorManager: OAuth2 token request failed for {}: {}",
                  host, res ? std::to_string(res->status) : "connection error");
        return "";
    }

    try {
        auto j = nlohmann::json::parse(res->body);
        return j.value("access_token", "");
    } catch (...) {
        return "";
    }
}

// ════════════════════════════════════════════════════════════════
// AUTHENTICATED GET
// ════════════════════════════════════════════════════════════════

std::pair<int, nlohmann::json> ApiPollerInstance::authenticated_get(
    const std::string& url,
    const nlohmann::json& settings,
    const std::string& cached_token) {

    std::string scheme, host, path;
    if (!parse_url(url, scheme, host, path)) {
        return {0, nullptr};
    }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    std::unique_ptr<httplib::Client> client;
    if (scheme == "https") {
        client = std::make_unique<httplib::Client>(std::string("https://") + host);
    } else {
        client = std::make_unique<httplib::Client>(host);
    }
#else
    auto client = std::make_unique<httplib::Client>(host);
#endif

    client->set_connection_timeout(10);
    client->set_read_timeout(30);

    // Build headers
    httplib::Headers headers;
    std::string auth_type = settings.value("auth_type", "none");

    if (auth_type == "oauth2" && !cached_token.empty()) {
        headers.emplace("Authorization", "Bearer " + cached_token);
    } else {
        headers = build_auth_headers(settings);
    }
    headers.emplace("Accept", "application/json");

    auto res = client->Get(path, headers);
    if (!res) {
        return {0, nullptr};
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(res->body);
    } catch (...) {
        body = nullptr;
    }

    return {res->status, body};
}

// ════════════════════════════════════════════════════════════════
// EVENT EXTRACTION
// ════════════════════════════════════════════════════════════════

std::vector<nlohmann::json> ApiPollerInstance::extract_events(const nlohmann::json& response) {
    std::vector<nlohmann::json> events;

    if (response.is_array()) {
        // Response is directly an array of events
        for (const auto& e : response) events.push_back(e);
    } else if (response.is_object()) {
        // Try common envelope patterns
        for (const auto& key : {"data", "value", "events", "items", "results",
                                 "alerts", "threats", "records", "logs"}) {
            if (response.contains(key) && response[key].is_array()) {
                for (const auto& e : response[key]) events.push_back(e);
                return events;
            }
        }
        // Single object could be a status/health response
        events.push_back(response);
    }

    return events;
}

// ════════════════════════════════════════════════════════════════
// TEST CONNECTION
// ════════════════════════════════════════════════════════════════

TestResult ApiPollerInstance::test_connection(const nlohmann::json& settings) {
    TestResult result;
    std::string url = settings.value("url", "");

    if (url.empty()) {
        result.message = "No URL configured";
        return result;
    }

    std::string auth_type = settings.value("auth_type", "none");
    std::string token;

    // If OAuth2, try to get a token first
    if (auth_type == "oauth2") {
        token = get_oauth2_token(settings);
        if (token.empty()) {
            result.message = "OAuth2 authentication failed — check tenant ID, client ID, and client secret";
            return result;
        }
    }

    auto [status, body] = authenticated_get(url, settings, token);

    if (status == 0) {
        result.message = "Connection failed — could not reach " + url;
        return result;
    }

    result.status_code = status;

    if (status == 401 || status == 403) {
        result.message = "Authentication failed (HTTP " + std::to_string(status) +
                         ") — check your credentials";
        return result;
    }

    if (status >= 400) {
        result.message = "API returned error HTTP " + std::to_string(status);
        if (body.is_object() && body.contains("error")) {
            result.message += ": " + body["error"].dump();
        }
        return result;
    }

    // Success — count events in response
    auto events = extract_events(body);
    result.ok = true;
    result.event_count = static_cast<int>(events.size());
    result.status_code = status;
    result.message = "Connected successfully (HTTP " + std::to_string(status) + ")";
    if (result.event_count > 0) {
        result.message += " — " + std::to_string(result.event_count) + " events available";
    }

    return result;
}

// ════════════════════════════════════════════════════════════════
// POLLER INSTANCE
// ════════════════════════════════════════════════════════════════

ApiPollerInstance::ApiPollerInstance(const std::string& connector_id,
                                     const nlohmann::json& settings,
                                     RingBuffer<>& buffer,
                                     PostgresStorageEngine& storage)
    : connector_id_(connector_id)
    , settings_(settings)
    , buffer_(buffer)
    , storage_(storage)
{}

ApiPollerInstance::~ApiPollerInstance() {
    stop();
}

void ApiPollerInstance::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&ApiPollerInstance::poll_loop, this);
}

void ApiPollerInstance::stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

/// Try to detect source type from a string (connector name or URL)
static std::string detect_source_hint(const std::string& text) {
    std::string lower;
    lower.resize(text.size());
    std::transform(text.begin(), text.end(), lower.begin(),
                   [](char c) { return std::tolower(c); });

    if (lower.find("unifi") != std::string::npos || lower.find("ubiquiti") != std::string::npos ||
        lower.find("/proxy/network/") != std::string::npos)
        return "unifi";
    if (lower.find("azure") != std::string::npos)    return "azure";
    if (lower.find("m365") != std::string::npos || lower.find("microsoft 365") != std::string::npos ||
        lower.find("office") != std::string::npos)
        return "m365";
    if (lower.find("fortigate") != std::string::npos || lower.find("fortinet") != std::string::npos)
        return "fortigate";
    if (lower.find("windows") != std::string::npos)  return "windows";
    if (lower.find("sentinel") != std::string::npos)  return "sentinelone";
    if (lower.find("crowdstrike") != std::string::npos || lower.find("falcon") != std::string::npos)
        return "crowdstrike";
    return "";
}

void ApiPollerInstance::poll_loop() {
    std::string url = settings_.value("url", "");
    std::string auth_type = settings_.value("auth_type", "none");
    int poll_interval = settings_.value("poll_interval_sec", 60);
    if (poll_interval < 5) poll_interval = 5;

    std::string source_label = settings_.value("source_label", "");
    // Auto-detect from connector name or URL if not explicitly set
    if (source_label.empty()) {
        std::string connector_name = settings_.value("_connector_name", "");
        source_label = detect_source_hint(connector_name);
    }
    if (source_label.empty()) {
        source_label = detect_source_hint(url);
    }
    if (source_label.empty()) source_label = "rest_api";

    LOG_INFO("ConnectorManager [{}]: source_label resolved to '{}'", connector_id_, source_label);

    LOG_INFO("ConnectorManager: starting poller for connector {} (url={}, interval={}s)",
             connector_id_, url, poll_interval);

    // Update connector status to running
    auto rec = storage_.get_connector(connector_id_);
    if (rec) {
        auto c = *rec;
        c.status = "running";
        c.updated_at = now_ms();
        storage_.update_connector(c);
    }

    while (running_.load(std::memory_order_relaxed)) {
        // Refresh OAuth2 token if needed
        if (auth_type == "oauth2") {
            auto now = std::chrono::steady_clock::now();
            if (cached_token_.empty() || now >= token_expiry_) {
                cached_token_ = get_oauth2_token(settings_);
                token_expiry_ = now + std::chrono::minutes(50);
                if (cached_token_.empty()) {
                    LOG_ERROR("ConnectorManager [{}]: OAuth2 token refresh failed", connector_id_);
                    // Wait before retrying
                    for (int i = 0; i < 300 && running_.load(); ++i)
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
            }
        }

        // Fetch
        auto [status, body] = authenticated_get(url, settings_, cached_token_);

        if (status == 0) {
            LOG_WARN("ConnectorManager [{}]: connection failed to {}", connector_id_, url);
        } else if (status == 401 || status == 403) {
            LOG_WARN("ConnectorManager [{}]: auth failed (HTTP {}), clearing token", connector_id_, status);
            cached_token_.clear(); // Force token refresh next iteration
        } else if (status >= 200 && status < 300 && !body.is_null()) {
            auto events = extract_events(body);
            for (const auto& evt : events) {
                std::string json_str = evt.dump();
                if (json_str.size() < RawMessage::MAX_SIZE) {
                    RawMessage msg;
                    msg.set(json_str.c_str(), json_str.size(), 443, source_label.c_str(),
                            source_label.c_str());
                    if (!buffer_.try_push(msg)) {
                        buffer_.record_drop();
                    }
                    event_count_.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Update event count in DB periodically (every poll)
            auto r = storage_.get_connector(connector_id_);
            if (r) {
                auto c = *r;
                c.event_count = static_cast<int64_t>(event_count_.load());
                c.updated_at = now_ms();
                storage_.update_connector(c);
            }
        } else {
            LOG_WARN("ConnectorManager [{}]: HTTP {} from {}", connector_id_, status, url);
        }

        // Sleep for poll interval (check running_ every 100ms)
        for (int i = 0; i < poll_interval * 10 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // Update connector status to stopped
    auto r2 = storage_.get_connector(connector_id_);
    if (r2) {
        auto c = *r2;
        c.status = "stopped";
        c.updated_at = now_ms();
        storage_.update_connector(c);
    }

    LOG_INFO("ConnectorManager: poller stopped for connector {} (events: {})",
             connector_id_, event_count_.load());
}

// ════════════════════════════════════════════════════════════════
// CONNECTOR MANAGER
// ════════════════════════════════════════════════════════════════

ConnectorManager::ConnectorManager(RingBuffer<>& buffer, PostgresStorageEngine& storage)
    : buffer_(buffer), storage_(storage) {}

ConnectorManager::~ConnectorManager() {
    stop();
}

void ConnectorManager::start() {
    if (running_.exchange(true)) return;
    sync();  // Initial sync
    sync_thread_ = std::thread(&ConnectorManager::sync_loop, this);
    LOG_INFO("ConnectorManager started");
}

void ConnectorManager::stop() {
    if (!running_.exchange(false)) return;
    if (sync_thread_.joinable()) sync_thread_.join();

    std::lock_guard<std::mutex> lock(mu_);
    for (auto& [id, poller] : pollers_) {
        poller->stop();
    }
    pollers_.clear();
    LOG_INFO("ConnectorManager stopped");
}

void ConnectorManager::sync() {
    auto connectors = storage_.get_connectors();
    std::lock_guard<std::mutex> lock(mu_);

    // Build set of connector IDs that should be running
    std::unordered_map<std::string, nlohmann::json> should_run;
    for (const auto& c : connectors) {
        if (c.enabled && c.type == "rest_api") {
            try {
                auto settings = nlohmann::json::parse(c.settings_json);
                if (!settings.value("url", "").empty()) {
                    // Inject connector name so poll_loop can derive source hint
                    settings["_connector_name"] = c.name;
                    should_run[c.id] = settings;
                }
            } catch (...) {}
        }
    }

    // Stop pollers for connectors that are no longer enabled/exist
    std::vector<std::string> to_remove;
    for (auto& [id, poller] : pollers_) {
        if (should_run.find(id) == should_run.end()) {
            LOG_INFO("ConnectorManager: stopping removed/disabled connector {}", id);
            poller->stop();
            to_remove.push_back(id);
        }
    }
    for (const auto& id : to_remove) {
        pollers_.erase(id);
    }

    // Start pollers for newly enabled connectors
    for (auto& [id, settings] : should_run) {
        if (pollers_.find(id) == pollers_.end()) {
            LOG_INFO("ConnectorManager: starting new poller for connector {}", id);
            auto poller = std::make_unique<ApiPollerInstance>(id, settings, buffer_, storage_);
            poller->start();
            pollers_[id] = std::move(poller);
        }
    }
}

void ConnectorManager::sync_loop() {
    // Re-sync every 15 seconds to pick up changes
    while (running_.load(std::memory_order_relaxed)) {
        for (int i = 0; i < 150 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (running_.load()) {
            sync();
        }
    }
}

void ConnectorManager::on_connector_changed(const std::string& /*connector_id*/) {
    // Immediate re-sync
    sync();
}

TestResult ConnectorManager::test_connection(const nlohmann::json& settings) {
    return ApiPollerInstance::test_connection(settings);
}

} // namespace outpost
