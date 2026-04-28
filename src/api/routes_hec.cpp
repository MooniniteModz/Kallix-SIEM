// HTTP Event Collector (HEC) — Splunk-compatible ingestion endpoint
//
// Supports:
//   POST /services/collector         — Splunk-compatible path
//   POST /services/collector/event   — Splunk-compatible alternate path
//   POST /api/hec/v1                 — Outpost native path
//
// Auth: "Authorization: Splunk <token>" or "Authorization: Bearer <token>"
//
// Payload (single event):
//   {"time":1234567890.123, "host":"myhost", "source":"mysrc",
//    "sourcetype":"cef", "event": {...} }
//
// Payload (batch): newline-delimited JSON objects (NOT a JSON array).
//
// sourcetype maps to the parser hint — use "cef", "azure", "fortigate",
// "windows", "syslog", etc. to route events to the right parser.

#include "api/server.h"
#include "common/logger.h"
#include "common/utils.h"
#include <nlohmann/json.hpp>
#include <sstream>

namespace outpost {

// ── Token extraction ──
// Accepts "Authorization: Splunk <token>" or "Authorization: Bearer <token>"
static std::string extract_hec_token(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return "";
    const auto& val = it->second;
    if (val.size() > 7 && val.substr(0, 7) == "Splunk ") return val.substr(7);
    if (val.size() > 7 && val.substr(0, 7) == "Bearer ") return val.substr(7);
    return "";
}

static void hec_error(httplib::Response& res, int http_status,
                      int code, const std::string& text) {
    res.status = http_status;
    res.set_content(
        nlohmann::json({{"text", text}, {"code", code}}).dump(),
        "application/json");
}

// ── Process one parsed HEC JSON object, push to ring buffer ──
static bool process_hec_event(const nlohmann::json& obj,
                               RingBuffer<>& buffer,
                               const std::string& remote_addr) {
    // Extract HEC envelope fields
    std::string host       = obj.value("host",       remote_addr);
    std::string source     = obj.value("source",     "");
    std::string sourcetype = obj.value("sourcetype", "");

    // Normalize sourcetype → source hint used by the parser pipeline
    // Strip common prefixes like "aws:cloudtrail" → "cloudtrail", etc.
    std::string hint = sourcetype;
    {
        auto colon = hint.rfind(':');
        if (colon != std::string::npos) hint = hint.substr(colon + 1);
        std::transform(hint.begin(), hint.end(), hint.begin(), ::tolower);
        // Map common sourcetype aliases to our internal hints
        if (hint == "wineventlog" || hint == "xmlwineventlog") hint = "windows";
        if (hint == "common:cef"  || hint == "arcsight:cef")   hint = "cef";
        if (hint == "syslog" || hint.empty())                   hint = "syslog";
    }

    // Build the payload pushed into the ring buffer
    nlohmann::json payload;
    if (obj.contains("event")) {
        auto& ev = obj["event"];
        if (ev.is_object()) {
            payload = ev;
        } else if (ev.is_string()) {
            // Raw string event — wrap it so parsers can handle it
            std::string raw_str = ev.get<std::string>();
            // If it looks like CEF, pass it through directly
            if (raw_str.find("CEF:") != std::string::npos) {
                // Push the raw string directly — CEF parser will pick it up
                RawMessage msg;
                msg.set(raw_str.c_str(), raw_str.size(), 0,
                        host.c_str(), "cef");
                return buffer.try_push(msg);
            }
            payload["message"] = raw_str;
        } else {
            return false;
        }
    } else {
        // No "event" wrapper — treat the whole object as the event
        payload = obj;
    }

    // Inject HEC metadata so parsers / the hinted fallback can use it
    if (!host.empty())   payload["_hec_host"]       = host;
    if (!source.empty()) payload["_hec_source"]      = source;
    if (!sourcetype.empty()) payload["_hec_sourcetype"] = sourcetype;

    // Override timestamp if provided in envelope
    if (obj.contains("time") && obj["time"].is_number()) {
        double t = obj["time"].get<double>();
        int64_t ms = static_cast<int64_t>(t * 1000.0);
        payload["_hec_time_ms"] = ms;
    }

    std::string json_str = payload.dump();
    if (json_str.size() >= RawMessage::MAX_SIZE) {
        LOG_WARN("HEC: event too large ({} bytes), dropping", json_str.size());
        return false;
    }

    RawMessage msg;
    msg.set(json_str.c_str(), json_str.size(), 0,
            host.c_str(), hint.c_str());
    return buffer.try_push(msg);
}

void ApiServer::register_hec_routes() {
    // ── HEC handler — shared across all three paths ──
    auto hec_handler = [this](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "application/json");

        // Token validation — always required
        if (config_.hec_token.empty()) {
            hec_error(res, 503, 9, "HEC endpoint not configured — set hec.token in outpost.yaml");
            return;
        }
        std::string token = extract_hec_token(req);
        if (token.empty()) {
            hec_error(res, 401, 2, "Token is required");
            return;
        }
        if (token != config_.hec_token) {
            hec_error(res, 403, 4, "Invalid token");
            return;
        }

        if (req.body.empty()) {
            hec_error(res, 400, 5, "No data");
            return;
        }

        int accepted = 0;
        int dropped  = 0;

        // Parse body — may be a single JSON object or newline-delimited batch
        std::istringstream stream(req.body);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.empty() || line == "\r") continue;
            // Strip trailing \r (Windows line endings)
            if (!line.empty() && line.back() == '\r') line.pop_back();

            try {
                auto obj = nlohmann::json::parse(line);
                std::string remote = req.remote_addr;
                if (process_hec_event(obj, buffer_, remote)) {
                    ++accepted;
                } else {
                    ++dropped;
                    buffer_.record_drop();
                }
            } catch (const std::exception& ex) {
                LOG_DEBUG("HEC: JSON parse error: {}", ex.what());
                hec_error(res, 400, 6, std::string("Invalid JSON: ") + ex.what());
                return;
            }
        }

        if (accepted == 0 && dropped > 0) {
            hec_error(res, 503, 9, "Server is busy");
            return;
        }

        LOG_DEBUG("HEC: accepted {} event(s) from {}", accepted, req.remote_addr);
        res.set_content(
            nlohmann::json({{"text", "Success"}, {"code", 0}}).dump(),
            "application/json");
    };

    // ── Splunk-compatible paths ──
    server_.Post("/services/collector",       hec_handler);
    server_.Post("/services/collector/event", hec_handler);

    // ── Outpost native path ──
    server_.Post("/api/hec/v1", hec_handler);

    LOG_INFO("HEC endpoint registered: POST /services/collector  POST /api/hec/v1");
}

} // namespace outpost
