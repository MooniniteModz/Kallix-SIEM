#pragma once

#include <string>
#include <vector>

namespace outpost {

struct AuthConfig {
    std::string default_admin_user = "admin";
    std::string default_admin_pass = "";    // must be set via KALLIX_ADMIN_PASS env var
    int         session_ttl_hours  = 24;
    int         min_password_length = 12;
    bool        require_uppercase   = true;
    bool        require_lowercase   = true;
    bool        require_digit       = true;
    bool        require_special     = true;
    int         max_login_attempts  = 5;     // per window
    int         login_window_sec    = 300;   // 5-minute window
    int         lockout_duration_sec = 900;  // 15-minute lockout
};

/// Generate a random 32-byte hex salt
std::string generate_salt();

/// Hash password with PBKDF2-HMAC-SHA256 (100k iterations), returns hex string
std::string hash_password(const std::string& password, const std::string& salt);

/// Verify password against stored salt + hash (constant-time comparison)
bool verify_password(const std::string& password,
                     const std::string& salt,
                     const std::string& stored_hash);

/// Generate a cryptographically secure session token (64 hex chars)
std::string generate_session_token();

/// SHA-256 hash of input, returned as lowercase hex string
std::string sha256_hex(const std::string& input);

/// Validate password against enterprise policy; returns empty string if OK,
/// or a human-readable error describing what's wrong.
std::string validate_password_policy(const std::string& password, const AuthConfig& config);

} // namespace outpost
