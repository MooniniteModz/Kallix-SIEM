#include "common/event.h"

namespace outpost {

std::string to_string(SourceType t) {
    switch (t) {
        case SourceType::FortiGate: return "fortigate";
        case SourceType::Windows:   return "windows";
        case SourceType::M365:      return "m365";
        case SourceType::Azure:     return "azure";
        case SourceType::Syslog:    return "syslog";
        default:                    return "unknown";
    }
}

std::string to_string(Severity s) {
    switch (s) {
        case Severity::Emergency: return "emergency";
        case Severity::Alert:     return "alert";
        case Severity::Critical:  return "critical";
        case Severity::Error:     return "error";
        case Severity::Warning:   return "warning";
        case Severity::Notice:    return "notice";
        case Severity::Info:      return "info";
        case Severity::Debug:     return "debug";
        default:                  return "unknown";
    }
}

std::string to_string(Category c) {
    switch (c) {
        case Category::Auth:     return "auth";
        case Category::Network:  return "network";
        case Category::Endpoint: return "endpoint";
        case Category::Cloud:    return "cloud";
        case Category::System:   return "system";
        default:                 return "unknown";
    }
}

std::string to_string(Outcome o) {
    switch (o) {
        case Outcome::Success: return "success";
        case Outcome::Failure: return "failure";
        default:               return "unknown";
    }
}

SourceType source_type_from_string(const std::string& s) {
    if (s == "fortigate") return SourceType::FortiGate;
    if (s == "windows")   return SourceType::Windows;
    if (s == "m365")      return SourceType::M365;
    if (s == "azure")     return SourceType::Azure;
    if (s == "syslog")    return SourceType::Syslog;
    return SourceType::Unknown;
}

Severity severity_from_int(int val) {
    if (val < 0) val = 0;
    if (val > 7) val = 7;
    return static_cast<Severity>(val);
}

Severity severity_from_string(const std::string& s) {
    if (s == "emergency") return Severity::Emergency;
    if (s == "alert")     return Severity::Alert;
    if (s == "critical")  return Severity::Critical;
    if (s == "error")     return Severity::Error;
    if (s == "warning")   return Severity::Warning;
    if (s == "notice")    return Severity::Notice;
    if (s == "info")      return Severity::Info;
    if (s == "debug")     return Severity::Debug;
    return Severity::Info;
}

Category category_from_string(const std::string& s) {
    if (s == "auth")     return Category::Auth;
    if (s == "network")  return Category::Network;
    if (s == "endpoint") return Category::Endpoint;
    if (s == "cloud")    return Category::Cloud;
    if (s == "system")   return Category::System;
    return Category::Unknown;
}

Outcome outcome_from_string(const std::string& s) {
    if (s == "success") return Outcome::Success;
    if (s == "failure") return Outcome::Failure;
    return Outcome::Unknown;
}

nlohmann::json event_to_json(const Event& e) {
    return {
        {"event_id",    e.event_id},
        {"timestamp",   e.timestamp},
        {"received_at", e.received_at},
        {"source_type", to_string(e.source_type)},
        {"source_host", e.source_host},
        {"severity",    to_string(e.severity)},
        {"category",    to_string(e.category)},
        {"action",      e.action},
        {"outcome",     to_string(e.outcome)},
        {"src_ip",      e.src_ip},
        {"dst_ip",      e.dst_ip},
        {"src_port",    e.src_port},
        {"dst_port",    e.dst_port},
        {"user",        e.user},
        {"user_agent",  e.user_agent},
        {"resource",    e.resource},
        {"raw",         e.raw},
        {"metadata",    e.metadata}
    };
}

} // namespace outpost
