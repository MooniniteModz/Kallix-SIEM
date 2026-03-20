#include "parser/syslog_parser.h"
#include "common/utils.h"

#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>

namespace outpost {

std::optional<Event> SyslogParser::parse(const RawMessage& raw) {
    std::string line = raw.as_string();
    if (line.empty()) return std::nullopt;

    Event event;
    event.event_id    = generate_uuid();
    event.received_at = now_ms();
    event.source_type = SourceType::Syslog;
    event.raw         = line;
    event.timestamp   = event.received_at;  // default; overridden if we parse one

    size_t pos = 0;

    // ── Parse priority <NNN> ──
    if (line[0] == '<') {
        auto gt = line.find('>', 1);
        if (gt != std::string::npos && gt < 5) {
            int pri = std::atoi(line.substr(1, gt - 1).c_str());
            int facility, severity;
            parse_priority(pri, facility, severity);
            event.severity = severity_from_int(severity);
            event.metadata["facility"] = facility;
            event.metadata["priority"] = pri;
            pos = gt + 1;
        }
    }

    // ── Try RFC 5424: version SP timestamp SP hostname SP app-name ... ──
    // RFC 5424 starts with version number after priority: <PRI>VERSION
    if (pos < line.size() && line[pos] >= '1' && line[pos] <= '9') {
        // Likely RFC 5424 — version followed by space
        size_t ver_end = line.find(' ', pos);
        if (ver_end != std::string::npos) {
            event.metadata["syslog_version"] = line.substr(pos, ver_end - pos);
            pos = ver_end + 1;

            // Timestamp (ISO 8601 or NILVALUE "-")
            size_t ts_end = line.find(' ', pos);
            if (ts_end != std::string::npos) {
                std::string ts = line.substr(pos, ts_end - pos);
                if (ts != "-") {
                    // Parse ISO 8601 timestamp
                    std::tm tm{};
                    std::istringstream ss(ts);
                    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                    if (!ss.fail()) {
                        event.timestamp = static_cast<int64_t>(timegm(&tm)) * 1000;
                    }
                }
                pos = ts_end + 1;
            }

            // Hostname
            size_t host_end = line.find(' ', pos);
            if (host_end != std::string::npos) {
                event.source_host = line.substr(pos, host_end - pos);
                if (event.source_host == "-") event.source_host = raw.source_addr;
                pos = host_end + 1;
            }

            // App-name
            size_t app_end = line.find(' ', pos);
            if (app_end != std::string::npos) {
                std::string app = line.substr(pos, app_end - pos);
                if (app != "-") event.metadata["app_name"] = app;
                pos = app_end + 1;
            }

            // ProcID
            size_t pid_end = line.find(' ', pos);
            if (pid_end != std::string::npos) {
                std::string pid = line.substr(pos, pid_end - pos);
                if (pid != "-") event.metadata["proc_id"] = pid;
                pos = pid_end + 1;
            }

            // MsgID
            size_t mid_end = line.find(' ', pos);
            if (mid_end != std::string::npos) {
                std::string mid = line.substr(pos, mid_end - pos);
                if (mid != "-") event.metadata["msg_id"] = mid;
                pos = mid_end + 1;
            }

            // Skip structured data (everything in [...])
            if (pos < line.size() && line[pos] == '[') {
                while (pos < line.size() && line[pos] != ' ') ++pos;
                if (pos < line.size()) ++pos;  // skip space after SD
            } else if (pos < line.size() && line[pos] == '-') {
                pos += 1;
                if (pos < line.size() && line[pos] == ' ') ++pos;
            }
        }
    } else {
        // ── RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG ──
        // Timestamp: "Mar 11 10:30:00" (15 chars)
        if (pos + 15 < line.size()) {
            std::string ts_str = line.substr(pos, 15);
            std::tm tm{};
            std::istringstream ss(ts_str);
            ss >> std::get_time(&tm, "%b %d %H:%M:%S");
            if (!ss.fail()) {
                // RFC 3164 doesn't include year; use current year
                auto now = std::chrono::system_clock::now();
                auto now_t = std::chrono::system_clock::to_time_t(now);
                std::tm now_tm{};
                gmtime_r(&now_t, &now_tm);
                tm.tm_year = now_tm.tm_year;
                event.timestamp = static_cast<int64_t>(timegm(&tm)) * 1000;
                pos += 16;  // 15 chars + space
            }
        }

        // Hostname (until next space)
        size_t host_end = line.find(' ', pos);
        if (host_end != std::string::npos) {
            event.source_host = line.substr(pos, host_end - pos);
            pos = host_end + 1;
        }
    }

    // Fallback source host
    if (event.source_host.empty()) {
        event.source_host = raw.source_addr;
    }

    // Everything remaining is the message body
    if (pos < line.size()) {
        event.resource = line.substr(pos);
    }

    event.category = Category::System;  // default for generic syslog
    event.action   = "syslog";

    return event;
}

void SyslogParser::parse_priority(int priority, int& facility, int& severity) {
    facility = priority / 8;
    severity = priority % 8;
}

} // namespace outpost
