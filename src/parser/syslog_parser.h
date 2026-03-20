#pragma once

#include "parser/parser.h"

namespace outpost {

/// ────────────────────────────────────────────────────────────────
/// SyslogParser: parses generic RFC 3164 and RFC 5424 syslog.
///
/// This is the catch-all parser for Meraki, Nutanix, Linux, and
/// any other device that speaks standard syslog. It extracts:
///   - Priority (facility + severity)
///   - Timestamp
///   - Hostname
///   - Message body
/// ────────────────────────────────────────────────────────────────
class SyslogParser : public Parser {
public:
    std::optional<Event> parse(const RawMessage& raw) override;
    const char* name() const override { return "syslog"; }

private:
    /// Parse RFC 3164 priority value <N> into facility and severity
    void parse_priority(int priority, int& facility, int& severity);
};

} // namespace outpost
