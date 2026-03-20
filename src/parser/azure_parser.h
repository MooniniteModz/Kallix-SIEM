#pragma once

#include "parser/parser.h"

namespace outpost {

/// ────────────────────────────────────────────────────────────────
/// AzureParser: parses Azure Activity / Monitor log events.
///
/// These arrive as JSON from the HTTP poller. Key fields:
///   operationName, caller, resourceId, status, category,
///   properties, level
///
/// Critical operations:
///   - Microsoft.Authorization/roleAssignments/write
///   - Microsoft.Compute/virtualMachines/write
///   - Microsoft.Network/networkSecurityGroups/* 
///   - Microsoft.Resources/subscriptions/resourceGroups/delete
/// ────────────────────────────────────────────────────────────────
class AzureParser : public Parser {
public:
    std::optional<Event> parse(const RawMessage& raw) override;
    const char* name() const override { return "azure"; }

private:
    Category categorize_operation(const std::string& operation_name);
    std::string simplify_operation(const std::string& operation_name);
    Severity map_level(const std::string& level);
};

} // namespace outpost
