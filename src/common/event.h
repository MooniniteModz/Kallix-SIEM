#pragma once

#include <cstdint>
#include <string>
#include <nlohmann/json.hpp>

namespace outpost {

/// Log source type enum
enum class SourceType : uint8_t {
    FortiGate,
    Windows,
    M365,
    Azure,
    Syslog,
    Unknown
};

/// Event severity (maps to syslog severity 0-7)
enum class Severity : uint8_t {
    Emergency = 0,
    Alert     = 1,
    Critical  = 2,
    Error     = 3,
    Warning   = 4,
    Notice    = 5,
    Info      = 6,
    Debug     = 7
};

/// High-level event category
enum class Category : uint8_t {
    Auth,
    Network,
    Endpoint,
    Cloud,
    System,
    Unknown
};

/// Event outcome
enum class Outcome : uint8_t {
    Success,
    Failure,
    Unknown
};

/// ────────────────────────────────────────────────────────────────
/// Common Event Schema
/// Every log source normalizes into this struct before storage.
/// ────────────────────────────────────────────────────────────────
struct Event {
    // Identity
    std::string  event_id;        // UUID generated at parse time
    int64_t      timestamp;       // epoch milliseconds from source
    int64_t      received_at;     // epoch milliseconds when Outpost received it

    // Classification
    SourceType   source_type  = SourceType::Unknown;
    std::string  source_host;     // originating hostname or IP
    Severity     severity     = Severity::Info;
    Category     category     = Category::Unknown;
    std::string  action;          // login_success, deny, file_access, etc.
    Outcome      outcome      = Outcome::Unknown;

    // Network fields
    std::string  src_ip;
    std::string  dst_ip;
    uint16_t     src_port = 0;
    uint16_t     dst_port = 0;

    // Identity fields
    std::string  user;            // username or UPN
    std::string  user_agent;

    // Resource
    std::string  resource;        // target file, mailbox, VM, policy, etc.

    // Raw data
    std::string  raw;             // original unparsed log line

    // Extensible metadata (source-specific fields)
    nlohmann::json metadata = nlohmann::json::object();
};

// ── String conversion helpers ──
std::string to_string(SourceType t);
std::string to_string(Severity s);
std::string to_string(Category c);
std::string to_string(Outcome o);

SourceType  source_type_from_string(const std::string& s);
Severity    severity_from_int(int val);
Severity    severity_from_string(const std::string& s);
Category    category_from_string(const std::string& s);
Outcome     outcome_from_string(const std::string& s);

// ── JSON serialization ──
nlohmann::json event_to_json(const Event& e);

} // namespace outpost
