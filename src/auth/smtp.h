#pragma once
#include <string>

namespace outpost {

struct SmtpConfig {
    std::string host;
    int         port          = 25;
    std::string username;
    std::string password;
    std::string from          = "noreply@outpost.local";
    std::string from_name     = "Kallix SIEM";
    std::string ehlo_hostname = "kallix.local";  // sent in SMTP EHLO command
    bool        use_ssl       = false;  // SMTPS (port 465); false = plaintext (port 25/587)
    bool        enabled       = false;
    std::string base_url;               // e.g. "https://kallix.cloud" for email links
};

/// Send a plain-text email via SMTP.
/// Returns true on success. Logs errors via LOG_WARN/LOG_ERROR.
bool send_email(const SmtpConfig& cfg,
                const std::string& to,
                const std::string& subject,
                const std::string& body_text);

} // namespace outpost
