#include "parser/fortigate_parser.h"
#include "common/utils.h"
#include "common/logger.h"

#include <ctime>
#include <sstream>

namespace outpost {

std::optional<Event> FortiGateParser::parse(const RawMessage& raw) {
    std::string line = raw.as_string();

    // Quick check: FortiGate logs contain "logid=" or "devname="
    if (line.find("logid=") == std::string::npos &&
        line.find("devname=") == std::string::npos) {
        return std::nullopt;  // not a FortiGate log
    }

    auto kv = parse_kv(line);
    if (kv.empty()) return std::nullopt;

    return map_to_event(kv, raw);
}

std::unordered_map<std::string, std::string> FortiGateParser::parse_kv(const std::string& line) {
    std::unordered_map<std::string, std::string> result;

    // Skip syslog header if present (everything before first key=value)
    // FortiGate KV pairs start with known keys like "date=", "logid=", "devname="
    size_t start = 0;

    // Find the first key=value pattern (word followed by =)
    // Skip past syslog priority <NNN> and header if present
    if (!line.empty() && line[0] == '<') {
        auto gt = line.find('>');
        if (gt != std::string::npos) {
            start = gt + 1;
            // Skip whitespace after priority
            while (start < line.size() && line[start] == ' ') ++start;
        }
    }

    // Now parse key=value pairs
    size_t i = start;
    while (i < line.size()) {
        // Skip whitespace
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        if (i >= line.size()) break;

        // Find '='
        size_t eq = line.find('=', i);
        if (eq == std::string::npos) break;

        std::string key = line.substr(i, eq - i);
        i = eq + 1;

        // Parse value (may be quoted)
        std::string value;
        if (i < line.size() && line[i] == '"') {
            // Quoted value - find closing quote
            ++i;
            size_t close = line.find('"', i);
            if (close == std::string::npos) {
                value = line.substr(i);
                i = line.size();
            } else {
                value = line.substr(i, close - i);
                i = close + 1;
            }
        } else {
            // Unquoted value - read until space
            size_t end = i;
            while (end < line.size() && line[end] != ' ' && line[end] != '\t') ++end;
            value = line.substr(i, end - i);
            i = end;
        }

        if (!key.empty()) {
            result[key] = value;
        }
    }

    return result;
}

Event FortiGateParser::map_to_event(
    const std::unordered_map<std::string, std::string>& kv,
    const RawMessage& raw)
{
    Event event;
    event.event_id    = generate_uuid();
    event.received_at = now_ms();
    event.source_type = SourceType::FortiGate;
    event.raw         = raw.as_string();

    // Source host
    auto it = kv.find("devname");
    if (it != kv.end()) event.source_host = it->second;
    else event.source_host = std::string(raw.source_addr);

    // Timestamp
    auto date_it = kv.find("date");
    auto time_it = kv.find("time");
    if (date_it != kv.end() && time_it != kv.end()) {
        event.timestamp = parse_timestamp(date_it->second, time_it->second);
    } else {
        event.timestamp = event.received_at;
    }

    // Severity (FortiGate uses "level" field)
    auto level_it = kv.find("level");
    if (level_it != kv.end()) {
        const auto& lvl = level_it->second;
        if (lvl == "emergency")      event.severity = Severity::Emergency;
        else if (lvl == "alert")     event.severity = Severity::Alert;
        else if (lvl == "critical")  event.severity = Severity::Critical;
        else if (lvl == "error")     event.severity = Severity::Error;
        else if (lvl == "warning")   event.severity = Severity::Warning;
        else if (lvl == "notice")    event.severity = Severity::Notice;
        else if (lvl == "information") event.severity = Severity::Info;
        else                          event.severity = Severity::Info;
    }

    // Category and type
    std::string type, subtype;
    it = kv.find("type");    if (it != kv.end()) type = it->second;
    it = kv.find("subtype"); if (it != kv.end()) subtype = it->second;
    event.category = categorize(type, subtype);

    // Action
    it = kv.find("action");
    if (it != kv.end()) {
        event.action = it->second;
        event.outcome = map_outcome(it->second);
    }

    // Network fields
    it = kv.find("srcip");  if (it != kv.end()) event.src_ip = it->second;
    it = kv.find("dstip");  if (it != kv.end()) event.dst_ip = it->second;
    it = kv.find("srcport");
    if (it != kv.end()) {
        try { event.src_port = static_cast<uint16_t>(std::stoi(it->second)); } catch (...) {}
    }
    it = kv.find("dstport");
    if (it != kv.end()) {
        try { event.dst_port = static_cast<uint16_t>(std::stoi(it->second)); } catch (...) {}
    }

    // User
    it = kv.find("user"); if (it != kv.end()) event.user = it->second;

    // Store all KV pairs in metadata for full fidelity
    nlohmann::json meta = nlohmann::json::object();
    for (const auto& [k, v] : kv) {
        meta[k] = v;
    }
    event.metadata = meta;

    return event;
}

Category FortiGateParser::categorize(const std::string& type, const std::string& subtype) {
    if (type == "traffic")  return Category::Network;
    if (type == "utm")      return Category::Network;
    if (type == "event") {
        if (subtype == "vpn" || subtype == "user" || subtype == "authentication")
            return Category::Auth;
        if (subtype == "system") return Category::System;
        if (subtype == "endpoint") return Category::Endpoint;
    }
    return Category::Network;  // default for FortiGate
}

Outcome FortiGateParser::map_outcome(const std::string& action) {
    if (action == "accept" || action == "allow" || action == "pass" ||
        action == "login" || action == "tunnel-up")
        return Outcome::Success;
    if (action == "deny" || action == "block" || action == "drop" ||
        action == "close" || action == "tunnel-down" || action == "login-failed")
        return Outcome::Failure;
    return Outcome::Unknown;
}

int64_t FortiGateParser::parse_timestamp(const std::string& date, const std::string& time_str) {
    // FortiGate format: date=2026-03-11 time=10:30:00
    std::string combined = date + " " + time_str;
    std::tm tm{};
    std::istringstream ss(combined);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    if (ss.fail()) {
        return now_ms();
    }
    // mktime interprets as local time; use timegm for UTC
    time_t epoch = timegm(&tm);
    return static_cast<int64_t>(epoch) * 1000;
}

} // namespace outpost
