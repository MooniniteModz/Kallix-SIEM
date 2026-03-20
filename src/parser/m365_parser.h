#pragma once

#include "parser/parser.h"

namespace outpost {

/// ────────────────────────────────────────────────────────────────
/// M365Parser: parses Microsoft 365 Management Activity API events.
///
/// These arrive as JSON from the HTTP poller. Key operations:
///   UserLoggedIn, MailboxLogin, FileAccessed, FileModified,
///   Add member to role, Update user, Set-Mailbox, New-InboxRule
///
/// Critical detection fields:
///   - Operation, UserId, ClientIP, ResultStatus, UserAgent
///   - ExtendedProperties (for session tokens, auth details)
/// ────────────────────────────────────────────────────────────────
class M365Parser : public Parser {
public:
    std::optional<Event> parse(const RawMessage& raw) override;
    const char* name() const override { return "m365"; }

private:
    Category categorize_operation(const std::string& operation, const std::string& workload);
    std::string map_action(const std::string& operation);
    Outcome map_outcome(const std::string& result_status);
};

} // namespace outpost
