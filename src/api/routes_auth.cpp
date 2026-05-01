// ApiServer — Auth routes (login, logout, session) with rate limiting
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/utils.h"
#include "common/logger.h"
#include "auth/auth.h"
#include "auth/smtp.h"
#include "auth/totp.h"

#include <nlohmann/json.hpp>
#include <mutex>
#include <map>
#include <sstream>

namespace outpost {

// Extract the real client IP, preferring X-Real-IP set by nginx over the
// direct TCP peer (which is always 127.0.0.1 when behind a local proxy).
// Takes only the first token so a spoofed multi-value header can't pad the key.
static std::string client_ip(const httplib::Request& req) {
    auto it = req.headers.find("X-Real-IP");
    if (it != req.headers.end() && !it->second.empty()) {
        // Trim to first whitespace-or-comma token — no injection into rate-limit key
        const auto& v = it->second;
        auto end = v.find_first_of(", \t");
        return (end == std::string::npos) ? v : v.substr(0, end);
    }
    it = req.headers.find("X-Forwarded-For");
    if (it != req.headers.end() && !it->second.empty()) {
        const auto& v = it->second;
        auto end = v.find_first_of(", \t");
        return (end == std::string::npos) ? v : v.substr(0, end);
    }
    return req.remote_addr;
}

// Build a Set-Cookie header value for the session token
static std::string build_session_cookie(const std::string& token, int64_t ttl_hours, bool secure) {
    std::string c = "kallix_session=" + token
        + "; HttpOnly"
        + "; Path=/"
        + "; Max-Age=" + std::to_string(ttl_hours * 3600LL)
        + "; SameSite=Strict";
    if (secure) c += "; Secure";
    return c;
}

// Build a cookie header that clears the session
static std::string clear_session_cookie() {
    return "kallix_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict";
}

// ── Login rate limiter ──
struct LoginAttempt {
    int    count    = 0;
    int64_t first_attempt = 0;
    int64_t locked_until  = 0;
};
static std::mutex rate_mutex;
static std::map<std::string, LoginAttempt> login_attempts;

static bool is_rate_limited(const std::string& key, const AuthConfig& config) {
    std::lock_guard<std::mutex> lock(rate_mutex);
    int64_t now = now_ms();

    // Evict entries whose lockout and window have both expired to cap map size
    int64_t window_ms = static_cast<int64_t>(config.login_window_sec) * 1000;
    for (auto it = login_attempts.begin(); it != login_attempts.end(); ) {
        auto& a = it->second;
        bool expired = (a.locked_until > 0 && now >= a.locked_until) ||
                       (a.locked_until == 0 && a.first_attempt > 0 &&
                        (now - a.first_attempt) > window_ms);
        it = expired ? login_attempts.erase(it) : ++it;
    }

    auto it = login_attempts.find(key);
    if (it == login_attempts.end()) return false;
    auto& attempt = it->second;

    if (attempt.locked_until > 0 && now < attempt.locked_until) return true;
    return false;
}

static void record_failed_login(const std::string& key, const AuthConfig& config) {
    std::lock_guard<std::mutex> lock(rate_mutex);
    int64_t now = now_ms();
    auto& attempt = login_attempts[key];

    if (attempt.count == 0) {
        attempt.first_attempt = now;
    }
    attempt.count++;

    if (attempt.count >= config.max_login_attempts) {
        attempt.locked_until = now + static_cast<int64_t>(config.lockout_duration_sec) * 1000;
        LOG_WARN("Login rate limit triggered for '{}' — locked for {}s", key, config.lockout_duration_sec);
    }
}

static void record_successful_login(const std::string& key) {
    std::lock_guard<std::mutex> lock(rate_mutex);
    login_attempts.erase(key);
}

void ApiServer::register_auth_routes() {

    server_.Post("/api/auth/login", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string username = body.value("username", "");
            std::string password = body.value("password", "");

            if (username.empty() || password.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Username and password required"})", "application/json");
                return;
            }
            if (username.size() > 255 || password.size() > 1024) {
                res.status = 400;
                res.set_content(R"({"error":"Credential exceeds maximum length"})", "application/json");
                return;
            }

            // Rate limiting keyed on IP+username to block both credential stuffing and single-account brute-force
            std::string rate_key = client_ip(req) + ":" + username;
            if (is_rate_limited(rate_key, auth_config_)) {
                res.status = 429;
                res.set_content(R"({"error":"Too many login attempts. Please try again later."})", "application/json");
                return;
            }

            auto user = storage_.get_user_by_email(username);
            if (!user || !verify_password(password, user->salt, user->password_hash)) {
                record_failed_login(rate_key, auth_config_);
                res.status = 401;
                res.set_content(R"({"error":"Invalid username or password"})", "application/json");
                return;
            }

            record_successful_login(rate_key);

            // Force password change — return a short-lived change token
            if (user->force_password_change) {
                auto change_token = generate_session_token();
                int64_t expires = now_ms() + (15LL * 60 * 1000); // 15-minute window
                storage_.create_pending_change(change_token, user->user_id, expires);
                nlohmann::json result = {
                    {"password_change_required", true},
                    {"change_token", change_token}
                };
                res.set_content(result.dump(), "application/json");
                return;
            }

            // MFA required — return a short-lived pending token instead of a session
            if (user->mfa_enabled) {
                auto pending = generate_session_token();
                int64_t expires = now_ms() + (5LL * 60 * 1000); // 5-minute window
                storage_.create_pending_mfa(pending, user->user_id, expires);
                nlohmann::json result = {
                    {"mfa_required", true},
                    {"mfa_token", pending}
                };
                res.set_content(result.dump(), "application/json");
                return;
            }

            auto token = generate_session_token();
            int64_t now = now_ms();
            int64_t expires = now + (static_cast<int64_t>(auth_config_.session_ttl_hours) * 3600 * 1000);
            storage_.create_session(token, user->user_id, now, expires);

            storage_.cleanup_expired_sessions();

            res.set_header("Set-Cookie",
                build_session_cookie(token, auth_config_.session_ttl_hours, config_.secure_cookies));

            nlohmann::json result = {
                {"token", token},
                {"expires_at", expires},
                {"username", username},
                {"email", user->email},
                {"role", user->role},
                {"mfa_setup_required", true}  // always required — frontend gates until setup
            };
            res.set_content(result.dump(), "application/json");

        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Post("/api/auth/logout", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = extract_session_token(req);
        if (!token.empty()) storage_.delete_session(token);
        // Clear the session cookie regardless
        res.set_header("Set-Cookie", clear_session_cookie());
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    // ── Forgot password — generate and email a reset token ──
    server_.Post("/api/auth/forgot-password", [this](const httplib::Request& req, httplib::Response& res) {
        // Always return the same message to avoid revealing whether an email exists
        const char* ok_msg = R"({"status":"ok","message":"If that email is registered, a reset link has been sent."})";

        try {
            auto body = nlohmann::json::parse(req.body);
            std::string email = body.value("email", "");
            if (email.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Email required"})", "application/json");
                return;
            }

            // Rate limit by email — prefix key to keep separate from login attempts
            std::string rate_key = "reset:" + email;
            if (is_rate_limited(rate_key, auth_config_)) {
                res.set_content(ok_msg, "application/json");
                return;
            }
            record_failed_login(rate_key, auth_config_);

            auto user = storage_.get_user_by_email(email);
            if (!user) {
                // Don't reveal the email doesn't exist
                res.set_content(ok_msg, "application/json");
                return;
            }

            if (!smtp_config_.enabled) {
                LOG_WARN("Password reset requested for {} but SMTP is not configured", email);
                res.set_content(ok_msg, "application/json");
                return;
            }

            // Generate a full 64-hex-char token (32 random bytes); store only its hash
            std::string token = generate_session_token();
            int64_t expires = now_ms() + (60LL * 60 * 1000); // 1 hour
            storage_.create_reset_token(sha256_hex(token), user->user_id, expires);
            storage_.cleanup_expired_reset_tokens();

            std::string base_url = smtp_config_.base_url;
            if (base_url.empty()) base_url = "http://localhost:5173";
            std::string reset_link = base_url + "/reset-password?token=" + token;

            std::string display = user->first_name.empty() ? email : user->first_name + " " + user->last_name;
            std::string plain =
                "You requested a password reset for your Kallix SIEM account.\r\n\r\n"
                "Reset link (valid 1 hour):\r\n" + reset_link + "\r\n\r\n"
                "If you did not request this, you can safely ignore this email.\r\n\r\n"
                "-- Kallix SIEM";

            // Build the same HTML as admin-initiated reset
            std::string html_body =
                R"(<h1 style="margin:0 0 6px;font-size:26px;font-weight:800;color:#111827;letter-spacing:-0.5px;">Password Reset Request</h1>)"
                R"(<p style="margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.7;">Hi )" + display + R"(,<br>You requested a password reset for your <strong>Kallix SIEM</strong> account.</p>)"
                R"(<table cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;"><tr><td>)"
                R"(<a href=")" + reset_link + R"(" style="display:inline-block;background:#00d4aa;color:#0d1117;text-decoration:none;font-size:15px;font-weight:700;padding:14px 32px;border-radius:6px;">Reset My Password &#8594;</a>)"
                R"(</td></tr></table>)"
                R"(<div style="background:#fff7ed;border:1px solid #fed7aa;border-left:4px solid #f97316;border-radius:0 6px 6px 0;padding:14px 18px;margin-bottom:20px;">)"
                R"(<div style="font-size:13px;font-weight:700;color:#c2410c;margin-bottom:6px;">&#9201; This link expires in 1 hour</div>)"
                R"(<div style="font-family:'Courier New',Courier,monospace;font-size:11px;color:#6366f1;word-break:break-all;background:#fff;border:1px solid #e5e7eb;border-radius:4px;padding:8px 10px;">)" + reset_link + R"(</div>)"
                R"(</div>)"
                R"(<div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:14px 18px;">)"
                R"(<div style="font-size:12px;color:#6b7280;line-height:1.6;">If you did not request this reset, your password has not been changed. You can safely ignore this email.</div>)"
                R"(</div>)";

            // Reuse the same shell as the user-management emails
            std::string html_shell_str =
                R"(<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>)"
                R"(<body style="margin:0;padding:0;background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">)"
                R"(<div style="display:none;max-height:0;overflow:hidden;font-size:1px;color:#f0f2f5;">Reset your Kallix SIEM password using the link below.</div>)"
                R"(<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f2f5;padding:0;"><tr><td align="center" style="padding:40px 16px;">)"
                R"(<table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">)"
                R"(<tr><td style="background:#1a1f2e;padding:0;height:5px;font-size:0;">&nbsp;</td></tr>)"
                R"(<tr><td style="background:#1a1f2e;padding:28px 40px 24px;">)"
                R"(<table cellpadding="0" cellspacing="0" border="0" width="100%"><tr>)"
                R"(<td><span style="font-size:22px;font-weight:800;color:#ffffff;letter-spacing:-0.5px;"><span style="color:#00d4aa;">&#11835;</span> KALLIX</span>)"
                R"(<span style="font-size:11px;font-weight:600;color:#4ade80;letter-spacing:3px;text-transform:uppercase;margin-left:10px;vertical-align:middle;">SIEM</span></td>)"
                R"(<td align="right"><span style="display:inline-block;background:rgba(0,212,170,0.15);color:#00d4aa;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;padding:4px 10px;border-radius:4px;border:1px solid rgba(0,212,170,0.3);">Security Alert</span></td>)"
                R"(</tr></table></td></tr>)"
                R"(<tr><td style="padding:36px 40px;">)" + html_body + R"(</td></tr>)"
                R"(<tr><td style="padding:0 40px;"><div style="border-top:1px solid #e5e7eb;"></div></td></tr>)"
                R"(<tr><td style="padding:24px 40px;background:#f9fafb;">)"
                R"(<div style="font-size:11px;color:#9ca3af;line-height:1.7;">This is an automated security notification from <strong>Kallix SIEM</strong>.<br>Do not reply to this email.</div>)"
                R"(</td></tr></table></td></tr></table></body></html>)";

            send_email_html(smtp_config_, email, "Kallix SIEM — Password Reset", plain, html_shell_str);
        } catch (const std::exception& e) {
            LOG_WARN("forgot-password handler error: {}", e.what());
        } catch (...) {
            LOG_WARN("forgot-password handler: unknown error");
        }

        res.set_content(ok_msg, "application/json");
    });

    // ── Reset password — validate token and set new password ──
    server_.Post("/api/auth/reset-password", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string token        = body.value("token", "");
            std::string new_password = body.value("new_password", "");

            if (token.empty() || new_password.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"token and new_password required"})", "application/json");
                return;
            }

            auto rec = storage_.get_reset_token(sha256_hex(token));
            if (!rec) {
                res.status = 400;
                res.set_content(R"({"error":"Invalid or expired reset token"})", "application/json");
                return;
            }

            std::string policy_err = validate_password_policy(new_password, auth_config_);
            if (!policy_err.empty()) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", policy_err}}).dump(), "application/json");
                return;
            }

            auto salt = generate_salt();
            auto hash = hash_password(new_password, salt);
            storage_.update_user_password(rec->user_id, hash, salt);

            // Invalidate all existing sessions for this user so they must log in fresh
            storage_.delete_sessions_for_user(rec->user_id);

            // Delete using the same hashed form it was stored under
            storage_.delete_reset_token(sha256_hex(token));

            LOG_INFO("Password reset completed for user_id={}", rec->user_id);
            res.set_content(R"({"status":"ok","message":"Password updated successfully. Please log in."})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── Set password — first-login forced password change ──
    server_.Post("/api/auth/set-password", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string change_token = body.value("change_token", "");
            std::string new_password = body.value("new_password", "");

            if (change_token.empty() || new_password.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"change_token and new_password required"})", "application/json");
                return;
            }

            // Validate password policy BEFORE consuming the token so a bad password
            // doesn't burn the one-time token and lock the user out of retrying.
            std::string policy_err = validate_password_policy(new_password, auth_config_);
            if (!policy_err.empty()) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", policy_err}}).dump(), "application/json");
                return;
            }

            auto user_id_opt = storage_.consume_pending_change(change_token);
            if (!user_id_opt) {
                res.status = 401;
                res.set_content(R"({"error":"Invalid or expired session — please sign in again"})", "application/json");
                return;
            }

            auto salt = generate_salt();
            auto hash = hash_password(new_password, salt);
            storage_.update_user_password(*user_id_opt, hash, salt);
            storage_.set_force_password_change(*user_id_opt, false);

            // Find user for session creation
            std::optional<PostgresStorageEngine::UserRecord> user;
            for (auto& u : storage_.list_users()) {
                if (u.user_id == *user_id_opt) { user = u; break; }
            }
            if (!user) {
                res.status = 500;
                res.set_content(R"({"error":"User not found after password change"})", "application/json");
                return;
            }

            auto token = generate_session_token();
            int64_t now = now_ms();
            int64_t expires = now + (static_cast<int64_t>(auth_config_.session_ttl_hours) * 3600 * 1000);
            storage_.create_session(token, user->user_id, now, expires);
            storage_.cleanup_expired_sessions();

            res.set_header("Set-Cookie",
                build_session_cookie(token, auth_config_.session_ttl_hours, config_.secure_cookies));

            LOG_INFO("First-login password set for user_id={}", user->user_id);

            nlohmann::json result = {
                {"token", token}, {"expires_at", expires},
                {"username", user->username}, {"email", user->email}, {"role", user->role},
                {"mfa_setup_required", true}
            };
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── MFA: complete login with TOTP code or backup code ──
    server_.Post("/api/auth/mfa/challenge", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string mfa_token   = body.value("mfa_token", "");
            std::string code        = body.value("code", "");
            std::string backup_code = body.value("backup_code", "");

            if (mfa_token.empty() || (code.empty() && backup_code.empty())) {
                res.status = 400;
                res.set_content(R"({"error":"mfa_token and code or backup_code required"})", "application/json");
                return;
            }

            // Rate limit MFA attempts per IP to prevent TOTP brute-force
            std::string mfa_rate_key = "mfa:" + client_ip(req);
            if (is_rate_limited(mfa_rate_key, auth_config_)) {
                res.status = 429;
                res.set_content(R"({"error":"Too many MFA attempts. Please try again later."})", "application/json");
                return;
            }

            // Peek first (no delete) so a wrong code doesn't burn the token
            auto user_id_opt = storage_.peek_pending_mfa(mfa_token);
            if (!user_id_opt) {
                res.status = 401;
                res.set_content(R"({"error":"Invalid or expired MFA session — please sign in again"})", "application/json");
                return;
            }

            std::optional<PostgresStorageEngine::UserRecord> found;
            for (auto& u : storage_.list_users()) {
                if (u.user_id == *user_id_opt) { found = u; break; }
            }
            if (!found) {
                res.status = 400;
                res.set_content(R"({"error":"User not found"})", "application/json");
                return;
            }

            bool verified = false;

            if (!code.empty()) {
                verified = totp_verify(found->totp_secret, code);
            } else if (!backup_code.empty()) {
                auto codes_json = nlohmann::json::parse(found->backup_codes, nullptr, false);
                if (!codes_json.is_discarded() && codes_json.is_array()) {
                    std::string hash = totp_sha256(backup_code);
                    nlohmann::json remaining = nlohmann::json::array();
                    for (auto& h : codes_json) {
                        if (!verified && h.get<std::string>() == hash) { verified = true; continue; }
                        remaining.push_back(h);
                    }
                    if (verified) storage_.update_backup_codes(found->user_id, remaining.dump());
                }
            }

            if (!verified) {
                record_failed_login(mfa_rate_key, auth_config_);
                res.status = 400;
                res.set_content(R"({"error":"Invalid code — check your authenticator app and try again"})", "application/json");
                return;
            }

            record_successful_login(mfa_rate_key);
            // Code is correct — now consume the token (prevents replay)
            storage_.consume_pending_mfa(mfa_token);

            auto token = generate_session_token();
            int64_t now = now_ms();
            int64_t expires = now + (static_cast<int64_t>(auth_config_.session_ttl_hours) * 3600 * 1000);
            storage_.create_session(token, found->user_id, now, expires);
            storage_.cleanup_expired_sessions();

            res.set_header("Set-Cookie",
                build_session_cookie(token, auth_config_.session_ttl_hours, config_.secure_cookies));

            nlohmann::json result = {
                {"token", token}, {"expires_at", expires},
                {"username", found->username}, {"email", found->email}, {"role", found->role}
            };
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── MFA setup: generate secret + QR URI ──
    server_.Get("/api/auth/mfa/setup", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session) return;

        std::string secret = totp_generate_secret();
        storage_.set_user_totp(session->user_id, secret);

        std::string uri = totp_uri(secret, session->email);
        nlohmann::json result = {
            {"secret", secret},
            {"uri", uri},
            {"issuer", "Kallix SIEM"}
        };
        res.set_content(result.dump(), "application/json");
    });

    // ── MFA enable: verify first code + save backup codes ──
    server_.Post("/api/auth/mfa/enable", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string code = body.value("code", "");
            if (code.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"code required"})", "application/json");
                return;
            }

            std::optional<PostgresStorageEngine::UserRecord> user;
            for (auto& u : storage_.list_users()) {
                if (u.user_id == session->user_id) { user = u; break; }
            }
            if (!user || user->totp_secret.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Call /api/auth/mfa/setup first"})", "application/json");
                return;
            }
            if (!totp_verify(user->totp_secret, code)) {
                res.status = 400;
                res.set_content(R"({"error":"Invalid code — check your authenticator app clock"})", "application/json");
                return;
            }

            auto plain_codes = totp_generate_backup_codes();
            nlohmann::json hashes = nlohmann::json::array();
            for (auto& c : plain_codes) hashes.push_back(totp_sha256(c));

            storage_.enable_user_mfa(session->user_id, hashes.dump());
            LOG_INFO("MFA enabled for user_id={}", session->user_id);

            nlohmann::json result = {{"backup_codes", plain_codes}};
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── MFA disable: requires current password ──
    server_.Post("/api/auth/mfa/disable", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string password = body.value("password", "");
            if (password.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"password required"})", "application/json");
                return;
            }

            std::optional<PostgresStorageEngine::UserRecord> user;
            for (auto& u : storage_.list_users()) {
                if (u.user_id == session->user_id) { user = u; break; }
            }
            if (!user || !verify_password(password, user->salt, user->password_hash)) {
                res.status = 401;
                res.set_content(R"({"error":"Incorrect password"})", "application/json");
                return;
            }

            storage_.disable_user_mfa(session->user_id);
            LOG_INFO("MFA disabled for user_id={}", session->user_id);
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── MFA status ──
    server_.Get("/api/auth/mfa/status", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session) return;
        for (auto& u : storage_.list_users()) {
            if (u.user_id == session->user_id) {
                nlohmann::json result = {{"mfa_enabled", u.mfa_enabled}};
                res.set_content(result.dump(), "application/json");
                return;
            }
        }
        res.status = 404;
        res.set_content(R"({"error":"User not found"})", "application/json");
    });

    server_.Get("/api/auth/me", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = extract_session_token(req);
        auto session = storage_.validate_session(token);
        if (!session) {
            res.status = 401;
            res.set_content(R"({"error":"Not authenticated"})", "application/json");
            return;
        }
        bool mfa_enabled = false;
        for (auto& u : storage_.list_users()) {
            if (u.user_id == session->user_id) { mfa_enabled = u.mfa_enabled; break; }
        }
        nlohmann::json result = {
            {"username", session->username},
            {"email", session->email},
            {"role", session->role},
            {"user_id", session->user_id},
            {"mfa_enabled", mfa_enabled}
        };
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace outpost
