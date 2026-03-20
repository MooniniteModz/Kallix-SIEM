#include "parser/m365_parser.h"
#include "common/utils.h"
#include "common/logger.h"

#include <ctime>
#include <sstream>

namespace outpost {

std::optional<Event> M365Parser::parse(const RawMessage& raw) {
    std::string data = raw.as_string();

    // M365 audit events are JSON with specific fields
    if (data.find("\"Operation\"") == std::string::npos &&
        data.find("\"operation\"") == std::string::npos) {
        return std::nullopt;
    }

    // Must also have a workload or CreationTime to confirm it's M365
    if (data.find("\"Workload\"") == std::string::npos &&
        data.find("\"CreationTime\"") == std::string::npos &&
        data.find("\"workload\"") == std::string::npos) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(data);

        Event event;
        event.event_id    = generate_uuid();
        event.received_at = now_ms();
        event.source_type = SourceType::M365;
        event.raw         = data;

        // ── Core fields ──
        std::string operation = j.value("Operation", j.value("operation", ""));
        std::string workload  = j.value("Workload", j.value("workload", ""));
        std::string user_id   = j.value("UserId", j.value("userId", ""));
        std::string client_ip = j.value("ClientIP", j.value("clientIP", ""));
        std::string result    = j.value("ResultStatus", j.value("resultStatus", ""));
        std::string user_agent_str = j.value("UserAgent", j.value("userAgent", ""));

        event.user       = user_id;
        event.src_ip     = client_ip;
        event.user_agent = user_agent_str;
        event.source_host = workload.empty() ? "M365" : workload;

        // Clean up ClientIP (may include port: "1.2.3.4:12345" or "[::1]:port")
        if (!event.src_ip.empty()) {
            // IPv4 with port
            auto colon = event.src_ip.rfind(':');
            if (colon != std::string::npos && event.src_ip.find('.') != std::string::npos) {
                // Only strip if it looks like ip:port (not IPv6)
                if (event.src_ip.find('[') == std::string::npos) {
                    event.src_ip = event.src_ip.substr(0, colon);
                }
            }
        }

        // ── Timestamp ──
        std::string ts = j.value("CreationTime", j.value("creationTime", ""));
        if (!ts.empty()) {
            std::tm tm{};
            std::istringstream ss(ts);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            if (!ss.fail()) {
                event.timestamp = static_cast<int64_t>(timegm(&tm)) * 1000;
            }
        }
        if (event.timestamp == 0) event.timestamp = event.received_at;

        // ── Classification ──
        event.category = categorize_operation(operation, workload);
        event.action   = map_action(operation);
        event.outcome  = map_outcome(result);

        // ── Resource (target object) ──
        // Could be SourceFileName, MailboxOwnerUPN, ObjectId, etc.
        if (j.contains("SourceFileName")) {
            event.resource = j["SourceFileName"].get<std::string>();
        } else if (j.contains("MailboxOwnerUPN")) {
            event.resource = j["MailboxOwnerUPN"].get<std::string>();
        } else if (j.contains("ObjectId")) {
            event.resource = j["ObjectId"].get<std::string>();
        } else if (j.contains("Target")) {
            // Entra ID events have Target array
            auto& targets = j["Target"];
            if (targets.is_array() && !targets.empty()) {
                for (auto& t : targets) {
                    if (t.contains("ID")) {
                        event.resource = t["ID"].get<std::string>();
                        break;
                    }
                }
            }
        }

        // ── Severity ──
        // M365 doesn't have severity per se; infer from operation
        if (operation.find("Failed") != std::string::npos ||
            result == "Failed" || result == "PartiallySucceeded") {
            event.severity = Severity::Warning;
        } else if (operation.find("Delete") != std::string::npos ||
                   operation.find("Remove") != std::string::npos) {
            event.severity = Severity::Notice;
        } else {
            event.severity = Severity::Info;
        }

        // Store full JSON as metadata
        event.metadata = j;

        return event;

    } catch (const std::exception& ex) {
        LOG_DEBUG("M365 parser JSON error: {}", ex.what());
        return std::nullopt;
    }
}

Category M365Parser::categorize_operation(const std::string& operation, const std::string& workload) {
    // Authentication events
    if (operation == "UserLoggedIn" || operation == "UserLoginFailed" ||
        operation == "MailboxLogin" || operation == "ForeignRealmIndexLogonInitialAuthUsingADFSFederatedToken" ||
        operation.find("Logon") != std::string::npos ||
        operation.find("Login") != std::string::npos ||
        operation.find("Password") != std::string::npos ||
        operation.find("token") != std::string::npos) {
        return Category::Auth;
    }

    // Azure AD / Entra ID admin operations
    if (workload == "AzureActiveDirectory" || workload == "AzureAD") {
        if (operation.find("member") != std::string::npos ||
            operation.find("role") != std::string::npos ||
            operation.find("User") != std::string::npos ||
            operation.find("Group") != std::string::npos) {
            return Category::Auth;
        }
        return Category::Cloud;
    }

    // Exchange operations
    if (workload == "Exchange") {
        return Category::Cloud;
    }

    // SharePoint / OneDrive
    if (workload == "SharePoint" || workload == "OneDrive") {
        return Category::Cloud;
    }

    return Category::Cloud;
}

std::string M365Parser::map_action(const std::string& operation) {
    // Map common M365 operations to normalized actions
    if (operation == "UserLoggedIn")     return "login_success";
    if (operation == "UserLoginFailed")  return "login_failure";
    if (operation == "MailboxLogin")     return "mailbox_login";
    if (operation == "FileAccessed")     return "file_access";
    if (operation == "FileModified")     return "file_modify";
    if (operation == "FileDeleted")      return "file_delete";
    if (operation == "FileUploaded")     return "file_upload";
    if (operation == "FileDownloaded")   return "file_download";
    if (operation == "FileSyncDownloadedFull") return "file_sync";
    if (operation == "SharingSet")       return "sharing_changed";
    if (operation == "AnonymousLinkCreated") return "anonymous_link_created";

    // Entra ID operations
    if (operation == "Add member to role.") return "role_assignment";
    if (operation == "Remove member from role.") return "role_removal";
    if (operation == "Add user." || operation == "Add User.") return "user_created";
    if (operation == "Delete user." || operation == "Delete User.") return "user_deleted";
    if (operation == "Update user." || operation == "Update User.") return "user_updated";
    if (operation == "Add member to group.") return "group_member_added";
    if (operation == "Remove member from group.") return "group_member_removed";
    if (operation == "Add group.") return "group_created";

    // Exchange operations
    if (operation == "New-InboxRule")    return "inbox_rule_created";
    if (operation == "Set-InboxRule")    return "inbox_rule_modified";
    if (operation == "Set-Mailbox")      return "mailbox_settings_changed";
    if (operation == "Add-MailboxPermission") return "mailbox_permission_added";
    if (operation == "MailItemsAccessed") return "mail_items_accessed";
    if (operation == "Send")             return "email_sent";
    if (operation == "SendAs")           return "email_sent_as";
    if (operation == "SendOnBehalf")     return "email_sent_on_behalf";

    // OAuth / App consent
    if (operation == "Consent to application.") return "app_consent";
    if (operation == "Add OAuth2PermissionGrant.") return "oauth_permission_grant";
    if (operation == "Add app role assignment to service principal.") return "app_role_assigned";

    // Fallback: lowercase and replace spaces
    std::string action = operation;
    std::transform(action.begin(), action.end(), action.begin(),
                   [](char c) { return c == ' ' ? '_' : std::tolower(c); });
    // Remove trailing periods
    while (!action.empty() && action.back() == '.') action.pop_back();
    return action;
}

Outcome M365Parser::map_outcome(const std::string& result_status) {
    if (result_status.empty() || result_status == "Succeeded" || result_status == "Success" ||
        result_status == "True" || result_status == "true") {
        return Outcome::Success;
    }
    if (result_status == "Failed" || result_status == "False" || result_status == "false") {
        return Outcome::Failure;
    }
    if (result_status == "PartiallySucceeded") {
        return Outcome::Success;  // treat as success but metadata has detail
    }
    return Outcome::Unknown;
}

} // namespace outpost
