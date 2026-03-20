#include "parser/windows_parser.h"
#include "common/utils.h"
#include "common/logger.h"

#include <algorithm>
#include <ctime>
#include <sstream>

namespace outpost {

std::optional<Event> WindowsParser::parse(const RawMessage& raw) {
    std::string data = raw.as_string();
    if (data.empty()) return std::nullopt;

    // Detect format
    if (data.find("<Event") != std::string::npos || 
        data.find("<event") != std::string::npos) {
        return parse_xml(data, raw);
    }

    // Try JSON format (agent-shipped)
    if (data.find("\"EventID\"") != std::string::npos ||
        data.find("\"eventid\"") != std::string::npos) {
        return parse_json(data, raw);
    }

    return std::nullopt;
}

std::optional<Event> WindowsParser::parse_xml(const std::string& xml, const RawMessage& raw) {
    Event event;
    event.event_id    = generate_uuid();
    event.received_at = now_ms();
    event.source_type = SourceType::Windows;
    event.raw         = xml;

    // ── System section ──
    // <EventID>4624</EventID>
    std::string event_id_str = extract_xml_value(xml, "EventID");
    int event_id = 0;
    if (!event_id_str.empty()) {
        try { event_id = std::stoi(event_id_str); } catch (...) {}
    }
    event.metadata["EventID"] = event_id;

    // <Computer>DC01.domain.local</Computer>
    event.source_host = extract_xml_value(xml, "Computer");
    if (event.source_host.empty()) {
        event.source_host = raw.source_addr;
    }

    // <TimeCreated SystemTime="2026-03-11T10:30:00.000000Z"/>
    {
        auto pos = xml.find("SystemTime=\"");
        if (pos != std::string::npos) {
            pos += 12; // length of SystemTime="
            auto end = xml.find('"', pos);
            if (end != std::string::npos) {
                std::string ts = xml.substr(pos, end - pos);
                std::tm tm{};
                std::istringstream ss(ts);
                ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                if (!ss.fail()) {
                    event.timestamp = static_cast<int64_t>(timegm(&tm)) * 1000;
                }
            }
        }
    }
    if (event.timestamp == 0) event.timestamp = event.received_at;

    // <Level>0</Level>  (0=LogAlways, 1=Critical, 2=Error, 3=Warning, 4=Info)
    std::string level_str = extract_xml_value(xml, "Level");
    if (!level_str.empty()) {
        int level = 0;
        try { level = std::stoi(level_str); } catch (...) {}
        switch (level) {
            case 1: event.severity = Severity::Critical; break;
            case 2: event.severity = Severity::Error; break;
            case 3: event.severity = Severity::Warning; break;
            case 4: event.severity = Severity::Info; break;
            default: event.severity = Severity::Info; break;
        }
    }

    // <Channel>Security</Channel>
    event.metadata["Channel"] = extract_xml_value(xml, "Channel");

    // <Provider Name="Microsoft-Windows-Security-Auditing"/>
    {
        auto pos = xml.find("Provider Name=\"");
        if (pos != std::string::npos) {
            pos += 15;
            auto end = xml.find('"', pos);
            if (end != std::string::npos) {
                event.metadata["Provider"] = xml.substr(pos, end - pos);
            }
        }
    }

    // <Keywords>0x8020000000000000</Keywords>
    std::string keywords = extract_xml_value(xml, "Keywords");
    event.metadata["Keywords"] = keywords;

    // ── EventData section ──
    // <Data Name="TargetUserName">jsmith</Data>
    std::string target_user = extract_xml_data(xml, "TargetUserName");
    std::string subject_user = extract_xml_data(xml, "SubjectUserName");
    event.user = !target_user.empty() ? target_user : subject_user;

    // Domain
    std::string target_domain = extract_xml_data(xml, "TargetDomainName");
    if (!target_domain.empty() && target_domain != "-") {
        event.metadata["Domain"] = target_domain;
        if (!event.user.empty()) {
            event.metadata["FullUser"] = target_domain + "\\" + event.user;
        }
    }

    // IP Address
    std::string ip = extract_xml_data(xml, "IpAddress");
    if (!ip.empty() && ip != "-") {
        event.src_ip = ip;
    }

    // Logon Type
    std::string logon_type = extract_xml_data(xml, "LogonType");
    if (!logon_type.empty()) {
        event.metadata["LogonType"] = logon_type;
    }

    // Process info
    std::string process_name = extract_xml_data(xml, "ProcessName");
    if (!process_name.empty()) {
        event.metadata["ProcessName"] = process_name;
    }

    std::string new_process = extract_xml_data(xml, "NewProcessName");
    if (!new_process.empty()) {
        event.metadata["NewProcessName"] = new_process;
        event.resource = new_process;
    }

    // Service info (for 7045)
    std::string service_name = extract_xml_data(xml, "ServiceName");
    if (!service_name.empty()) {
        event.metadata["ServiceName"] = service_name;
        event.resource = service_name;
    }

    // ── Classification ──
    event.category = categorize_event(event_id);
    event.action   = event_id_to_action(event_id);
    event.outcome  = determine_outcome(event_id, keywords);

    return event;
}

std::optional<Event> WindowsParser::parse_json(const std::string& data, const RawMessage& raw) {
    try {
        auto j = nlohmann::json::parse(data);

        Event event;
        event.event_id    = generate_uuid();
        event.received_at = now_ms();
        event.source_type = SourceType::Windows;
        event.raw         = data;

        int event_id = j.value("EventID", j.value("eventid", 0));
        event.metadata["EventID"] = event_id;

        event.source_host = j.value("Computer", j.value("computer", std::string(raw.source_addr)));
        event.user        = j.value("TargetUserName", j.value("SubjectUserName", ""));

        // Timestamp
        std::string ts = j.value("TimeCreated", j.value("timestamp", ""));
        if (!ts.empty()) {
            std::tm tm{};
            std::istringstream ss(ts);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            if (!ss.fail()) {
                event.timestamp = static_cast<int64_t>(timegm(&tm)) * 1000;
            }
        }
        if (event.timestamp == 0) event.timestamp = event.received_at;

        event.src_ip   = j.value("IpAddress", "");
        event.category = categorize_event(event_id);
        event.action   = event_id_to_action(event_id);
        event.outcome  = determine_outcome(event_id, j.value("Keywords", ""));
        event.metadata = j;  // store entire JSON as metadata

        return event;
    } catch (...) {
        return std::nullopt;
    }
}

std::string WindowsParser::extract_xml_value(const std::string& xml, const std::string& tag) {
    std::string open = "<" + tag;
    auto pos = xml.find(open);
    if (pos == std::string::npos) return "";

    // Skip to end of opening tag (handles attributes)
    auto gt = xml.find('>', pos + open.size());
    if (gt == std::string::npos) return "";

    // Check for self-closing tag
    if (xml[gt - 1] == '/') return "";

    auto close_tag = "</" + tag + ">";
    auto end = xml.find(close_tag, gt + 1);
    if (end == std::string::npos) return "";

    return xml.substr(gt + 1, end - gt - 1);
}

std::string WindowsParser::extract_xml_data(const std::string& xml, const std::string& attr_name) {
    // Look for: <Data Name="attr_name">value</Data>
    std::string search = "Name=\"" + attr_name + "\"";
    auto pos = xml.find(search);
    if (pos == std::string::npos) return "";

    auto gt = xml.find('>', pos + search.size());
    if (gt == std::string::npos) return "";
    if (xml[gt - 1] == '/') return "";  // self-closing

    auto close = xml.find("</Data>", gt + 1);
    if (close == std::string::npos) return "";

    return xml.substr(gt + 1, close - gt - 1);
}

Category WindowsParser::categorize_event(int event_id) {
    switch (event_id) {
        // Authentication events
        case 4624: case 4625: case 4648: case 4634:
        case 4647: case 4672: case 4768: case 4769:
        case 4771: case 4776:
            return Category::Auth;

        // Account management
        case 4720: case 4722: case 4723: case 4724:
        case 4725: case 4726: case 4738: case 4740:
        case 4732: case 4733: case 4756: case 4757:
            return Category::Auth;

        // Process / endpoint events
        case 4688: case 4689: case 7045: case 4697:
            return Category::Endpoint;

        // System events
        case 1102: case 4616: case 6005: case 6006:
            return Category::System;

        default:
            return Category::Endpoint;
    }
}

std::string WindowsParser::event_id_to_action(int event_id) {
    switch (event_id) {
        case 4624: return "login_success";
        case 4625: return "login_failure";
        case 4634: return "logoff";
        case 4647: return "user_initiated_logoff";
        case 4648: return "explicit_credential_login";
        case 4672: return "special_privilege_assigned";
        case 4688: return "process_created";
        case 4689: return "process_exited";
        case 4720: return "account_created";
        case 4722: return "account_enabled";
        case 4724: return "password_reset";
        case 4725: return "account_disabled";
        case 4726: return "account_deleted";
        case 4732: return "member_added_to_group";
        case 4733: return "member_removed_from_group";
        case 4738: return "account_changed";
        case 4740: return "account_locked_out";
        case 4756: return "member_added_to_universal_group";
        case 4768: return "kerberos_tgt_requested";
        case 4769: return "kerberos_service_ticket_requested";
        case 4771: return "kerberos_preauth_failed";
        case 4776: return "credential_validation";
        case 7045: return "service_installed";
        case 4697: return "service_installed_system";
        case 1102: return "audit_log_cleared";
        default:   return "windows_event_" + std::to_string(event_id);
    }
}

Outcome WindowsParser::determine_outcome(int event_id, const std::string& keywords) {
    // Audit success vs failure from Keywords
    // 0x8020000000000000 = Audit Success
    // 0x8010000000000000 = Audit Failure
    if (keywords.find("8020") != std::string::npos) return Outcome::Success;
    if (keywords.find("8010") != std::string::npos) return Outcome::Failure;

    // Fallback by event ID
    switch (event_id) {
        case 4624: case 4634: case 4647: case 4672:
        case 4688: case 4720: case 4722: case 4732:
        case 4768: case 4769:
            return Outcome::Success;
        case 4625: case 4771: case 4740:
            return Outcome::Failure;
        default:
            return Outcome::Unknown;
    }
}

} // namespace outpost
