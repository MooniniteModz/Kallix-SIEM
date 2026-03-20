#pragma once

#include "parser/parser.h"
#include <string>
#include <unordered_map>

namespace outpost {

/// ────────────────────────────────────────────────────────────────
/// WindowsParser: parses Windows Event Log entries.
///
/// Windows events arrive as XML (EVTX schema) or as JSON if shipped
/// by a forwarding agent. This parser handles both formats.
///
/// Key security events tracked:
///   4624/4625 - Logon success/failure
///   4648      - Explicit credential use
///   4720      - Account creation
///   4732      - Group membership change
///   7045      - Service installation
///   1102      - Audit log cleared
///   4688      - Process creation
///   4697      - Service installed
/// ────────────────────────────────────────────────────────────────
class WindowsParser : public Parser {
public:
    std::optional<Event> parse(const RawMessage& raw) override;
    const char* name() const override { return "windows"; }

private:
    /// Parse XML event log format
    std::optional<Event> parse_xml(const std::string& data, const RawMessage& raw);

    /// Parse JSON event log format (from agents that pre-convert)
    std::optional<Event> parse_json(const std::string& data, const RawMessage& raw);

    /// Extract a value between XML tags: <Tag>value</Tag>
    std::string extract_xml_value(const std::string& xml, const std::string& tag);

    /// Extract attribute from an XML element: <Tag Name="AttrName">value</Tag>
    std::string extract_xml_data(const std::string& xml, const std::string& attr_name);

    /// Categorize based on EventID
    Category categorize_event(int event_id);

    /// Map EventID to a human-readable action
    std::string event_id_to_action(int event_id);

    /// Determine outcome from keywords
    Outcome determine_outcome(int event_id, const std::string& keywords);
};

} // namespace outpost
