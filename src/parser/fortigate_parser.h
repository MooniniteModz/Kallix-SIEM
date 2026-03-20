#pragma once

#include "parser/parser.h"
#include <string>
#include <unordered_map>

namespace outpost {

/// ────────────────────────────────────────────────────────────────
/// FortiGateParser: parses FortiGate syslog messages.
///
/// FortiGate logs are key=value pairs, optionally with a syslog
/// header prefix. Example:
///   date=2026-03-11 time=10:30:00 logid="0001000014" type="traffic"
///   subtype="forward" srcip=10.0.1.50 dstip=8.8.8.8 action="accept" ...
///
/// The parser:
///   1. Strips the syslog header if present
///   2. Extracts all key=value pairs (handling quoted values)
///   3. Maps known keys to Event fields
///   4. Stores remaining keys in metadata JSON
/// ────────────────────────────────────────────────────────────────
class FortiGateParser : public Parser {
public:
    std::optional<Event> parse(const RawMessage& raw) override;
    const char* name() const override { return "fortigate"; }

private:
    /// Parse key=value pairs from a FortiGate log line
    std::unordered_map<std::string, std::string> parse_kv(const std::string& line);

    /// Map parsed KV pairs into the common Event schema
    Event map_to_event(const std::unordered_map<std::string, std::string>& kv,
                       const RawMessage& raw);

    /// Determine event category from FortiGate type/subtype
    Category categorize(const std::string& type, const std::string& subtype);

    /// Map FortiGate action to Outcome
    Outcome map_outcome(const std::string& action);

    /// Parse FortiGate date+time fields into epoch milliseconds
    int64_t parse_timestamp(const std::string& date, const std::string& time_str);
};

} // namespace outpost
