#include "parser/azure_parser.h"
#include "common/utils.h"
#include "common/logger.h"

#include <algorithm>
#include <ctime>
#include <sstream>

namespace outpost {

std::optional<Event> AzureParser::parse(const RawMessage& raw) {
    std::string data = raw.as_string();

    // Azure Activity logs have operationName and resourceId
    if (data.find("\"operationName\"") == std::string::npos) {
        return std::nullopt;
    }
    if (data.find("\"resourceId\"") == std::string::npos &&
        data.find("\"resourceUri\"") == std::string::npos) {
        return std::nullopt;
    }

    try {
        auto j = nlohmann::json::parse(data);

        Event event;
        event.event_id    = generate_uuid();
        event.received_at = now_ms();
        event.source_type = SourceType::Azure;
        event.raw         = data;

        // ── Core fields ──
        std::string operation = j.value("operationName", "");
        std::string caller    = j.value("caller", "");
        std::string resource  = j.value("resourceId", j.value("resourceUri", ""));
        std::string status    = "";
        std::string level     = j.value("level", "");

        // Status can be nested: { "status": { "value": "Succeeded" } }
        // or flat: { "status": "Succeeded" }
        if (j.contains("status")) {
            if (j["status"].is_object()) {
                status = j["status"].value("value", "");
            } else if (j["status"].is_string()) {
                status = j["status"].get<std::string>();
            }
        }
        // Also check resultType
        if (status.empty()) {
            status = j.value("resultType", "");
        }

        event.user        = caller;
        event.resource    = resource;
        event.source_host = "Azure";

        // ── Timestamp ──
        std::string ts = j.value("eventTimestamp", j.value("time", ""));
        if (!ts.empty()) {
            std::tm tm{};
            std::istringstream ss(ts);
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            if (!ss.fail()) {
                event.timestamp = static_cast<int64_t>(timegm(&tm)) * 1000;
            }
        }
        if (event.timestamp == 0) event.timestamp = event.received_at;

        // ── Source IP (from claims or httpRequest) ──
        if (j.contains("httpRequest")) {
            event.src_ip = j["httpRequest"].value("clientIpAddress", "");
        }
        if (event.src_ip.empty() && j.contains("claims")) {
            event.src_ip = j["claims"].value("ipaddr", "");
        }

        // ── Classification ──
        event.category = categorize_operation(operation);
        event.action   = simplify_operation(operation);
        event.severity = map_level(level);

        // Outcome
        if (status == "Succeeded" || status == "Started" || status == "Accepted") {
            event.outcome = Outcome::Success;
        } else if (status == "Failed") {
            event.outcome = Outcome::Failure;
        } else {
            event.outcome = Outcome::Unknown;
        }

        // Store full JSON as metadata
        event.metadata = j;

        // Subscription ID from resource path (added after metadata assignment)
        if (!resource.empty()) {
            auto sub_start = resource.find("/subscriptions/");
            if (sub_start != std::string::npos) {
                sub_start += 15;
                auto sub_end = resource.find('/', sub_start);
                if (sub_end != std::string::npos) {
                    event.metadata["SubscriptionId"] = resource.substr(sub_start, sub_end - sub_start);
                }
            }
        }

        return event;

    } catch (const std::exception& ex) {
        LOG_DEBUG("Azure parser JSON error: {}", ex.what());
        return std::nullopt;
    }
}

Category AzureParser::categorize_operation(const std::string& op) {
    // Authorization / IAM
    if (op.find("Authorization") != std::string::npos ||
        op.find("roleAssignment") != std::string::npos ||
        op.find("roleDefinition") != std::string::npos ||
        op.find("policyAssignment") != std::string::npos) {
        return Category::Auth;
    }

    // Network
    if (op.find("Network") != std::string::npos ||
        op.find("networkSecurityGroup") != std::string::npos ||
        op.find("publicIPAddress") != std::string::npos ||
        op.find("loadBalancer") != std::string::npos ||
        op.find("virtualNetwork") != std::string::npos) {
        return Category::Network;
    }

    // Compute / endpoint
    if (op.find("Compute") != std::string::npos ||
        op.find("virtualMachine") != std::string::npos) {
        return Category::Endpoint;
    }

    return Category::Cloud;
}

std::string AzureParser::simplify_operation(const std::string& operation) {
    // Azure ops look like: "Microsoft.Compute/virtualMachines/write"
    // Simplify to: "vm_write" or similar
    std::string op = operation;

    // Remove provider prefix (Microsoft.Xxx/)
    auto first_slash = op.find('/');
    if (first_slash != std::string::npos) {
        op = op.substr(first_slash + 1);
    }

    // Replace slashes with underscores, lowercase
    std::transform(op.begin(), op.end(), op.begin(), [](char c) {
        if (c == '/') return '_';
        return static_cast<char>(std::tolower(c));
    });

    return op;
}

Severity AzureParser::map_level(const std::string& level) {
    if (level == "Critical") return Severity::Critical;
    if (level == "Error")    return Severity::Error;
    if (level == "Warning")  return Severity::Warning;
    if (level == "Informational" || level == "Information") return Severity::Info;
    return Severity::Info;
}

} // namespace outpost
