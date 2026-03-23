#pragma once

#include <string>

namespace outpost {

struct AuthConfig {
    std::string default_admin_user = "admin";
    std::string default_admin_pass = "outpost";
    int         session_ttl_hours  = 24;
};

/// Generate a random 32-byte hex salt
std::string generate_salt();

/// Hash password with SHA-256(salt + password), returns hex string
std::string hash_password(const std::string& password, const std::string& salt);

/// Verify password against stored salt + hash
bool verify_password(const std::string& password,
                     const std::string& salt,
                     const std::string& stored_hash);

/// Generate a random session token (64 hex chars)
std::string generate_session_token();

} // namespace outpost
