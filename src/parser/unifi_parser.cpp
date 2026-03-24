#include "parser/unifi_parser.h"
#include "common/utils.h"

#include <nlohmann/json.hpp>
#include <ctime>

namespace outpost {

/// Try to parse an ISO 8601 timestamp string to epoch milliseconds
static int64_t parse_iso_timestamp(const std::string& ts) {
    if (ts.empty()) return now_ms();
    std::tm tm{};
    // Try parsing ISO 8601 format: 2025-07-25T19:44:30Z
    if (sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) >= 3) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
        time_t t = timegm(&tm);
        if (t >= 0) return static_cast<int64_t>(t) * 1000;
    }
    return now_ms();
}

std::optional<Event> UniFiParser::parse(const RawMessage& raw) {
    std::string line = raw.as_string();
    if (line.empty() || line[0] != '{') return std::nullopt;

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(line);
    } catch (...) {
        return std::nullopt;
    }

    if (!j.is_object()) return std::nullopt;

    // ── Detect UniFi host/device objects ──
    // UniFi hosts have fields like: id, hardwareId, type, ipAddress,
    // lastConnectionStateChange, firmwareVersion, model, name, etc.
    bool is_host = j.contains("hardwareId") || j.contains("firmwareVersion") ||
                   (j.contains("id") && j.contains("type") &&
                    (j.contains("ipAddress") || j.contains("ip")));

    // ── Detect UniFi alert/event objects ──
    // UniFi alerts/events may have: key, msg, datetime, site_id
    bool is_alert = j.contains("key") && (j.contains("msg") || j.contains("datetime"));

    // ── Detect UniFi site objects ──
    bool is_site = j.contains("siteId") || (j.contains("meta") && j.contains("statistics"));

    if (!is_host && !is_alert && !is_site) return std::nullopt;

    Event event;
    event.event_id    = generate_uuid();
    event.received_at = now_ms();
    event.source_type = SourceType::UniFi;
    event.raw         = line;
    event.source_host = raw.source_addr;

    if (is_host) {
        // ── Parse host/device data ──
        std::string device_name = j.value("name", j.value("hostname", ""));
        std::string device_id   = j.value("id", "");
        std::string hw_id       = j.value("hardwareId", "");
        std::string model       = j.value("model", "");
        std::string fw_version  = j.value("firmwareVersion", "");
        std::string ip          = j.value("ipAddress", j.value("ip", ""));
        std::string mac         = j.value("mac", "");
        std::string device_type = j.value("type", "device");
        bool is_blocked         = j.value("isBlocked", false);
        bool is_connected       = j.value("isConnected", true);
        std::string state_change = j.value("lastConnectionStateChange", "");
        std::string status_text = j.value("status", "");

        event.action   = "device_report";
        event.category = Category::Network;
        event.severity = is_blocked ? Severity::Warning : Severity::Info;
        event.outcome  = is_connected ? Outcome::Success : Outcome::Unknown;
        event.src_ip   = ip;
        event.resource = device_name.empty() ? device_id : device_name;
        event.timestamp = parse_iso_timestamp(state_change);

        // Determine device status
        std::string status = "online";
        if (is_blocked) status = "blocked";
        else if (!is_connected) status = "offline";
        else if (!status_text.empty()) status = status_text;

        event.metadata["device_id"]    = device_id;
        event.metadata["hardware_id"]  = hw_id;
        event.metadata["model"]        = model;
        event.metadata["firmware"]     = fw_version;
        event.metadata["mac"]          = mac;
        event.metadata["device_type"]  = device_type;
        event.metadata["device_name"]  = device_name;
        event.metadata["status"]       = status;
        event.metadata["is_blocked"]   = is_blocked;
        event.metadata["is_connected"] = is_connected;

        // Extract location if available (from site data or reportedState)
        if (j.contains("reportedState")) {
            auto& rs = j["reportedState"];
            if (rs.contains("latitude") && rs.contains("longitude")) {
                event.metadata["latitude"]  = rs["latitude"];
                event.metadata["longitude"] = rs["longitude"];
            }
            if (rs.contains("name")) {
                event.metadata["device_name"] = rs["name"].get<std::string>();
                if (event.resource.empty()) event.resource = rs["name"].get<std::string>();
            }
        }
        if (j.contains("latitude") && j.contains("longitude")) {
            event.metadata["latitude"]  = j["latitude"];
            event.metadata["longitude"] = j["longitude"];
        }

    } else if (is_alert) {
        // ── Parse alert/event data ──
        std::string msg      = j.value("msg", "");
        std::string key      = j.value("key", "");
        std::string datetime = j.value("datetime", "");
        std::string site_id  = j.value("site_id", j.value("siteId", ""));

        event.action   = key;
        event.category = Category::Network;
        event.resource = msg;
        event.timestamp = parse_iso_timestamp(datetime);

        // Map alert severity from key patterns
        if (key.find("EVT_IPS") != std::string::npos ||
            key.find("EVT_AD") != std::string::npos) {
            event.severity = Severity::Warning;
        } else if (key.find("critical") != std::string::npos) {
            event.severity = Severity::Critical;
        } else {
            event.severity = Severity::Info;
        }

        event.metadata["alert_key"] = key;
        event.metadata["site_id"]   = site_id;
        if (j.contains("src_ip"))  event.src_ip = j["src_ip"].get<std::string>();
        if (j.contains("dst_ip"))  event.dst_ip = j["dst_ip"].get<std::string>();
        if (j.contains("srcipGeo")) {
            auto& geo = j["srcipGeo"];
            if (geo.contains("latitude") && geo.contains("longitude")) {
                event.metadata["latitude"]  = geo["latitude"];
                event.metadata["longitude"] = geo["longitude"];
                if (geo.contains("city")) event.metadata["city"] = geo["city"];
            }
        }

    } else if (is_site) {
        // ── Parse site data ──
        std::string site_name = j.value("name", j.value("desc", ""));
        std::string site_id   = j.value("siteId", j.value("_id", ""));

        event.action   = "site_report";
        event.category = Category::System;
        event.severity = Severity::Info;
        event.resource = site_name;
        event.timestamp = now_ms();

        event.metadata["site_id"]   = site_id;
        event.metadata["site_name"] = site_name;

        if (j.contains("latitude") && j.contains("longitude")) {
            event.metadata["latitude"]  = j["latitude"];
            event.metadata["longitude"] = j["longitude"];
        }
    }

    return event;
}

} // namespace outpost
