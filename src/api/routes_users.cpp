// ApiServer — User management routes (admin-only CRUD)

#include "api/server.h"
#include "common/utils.h"
#include "common/logger.h"
#include "auth/auth.h"
#include "auth/smtp.h"

#include <nlohmann/json.hpp>

namespace outpost {

// ── Email HTML templates ──────────────────────────────────────────────────────

// Huntress/SentinelOne-inspired email shell — accent top bar, clean white body, branded footer
static std::string html_shell(const std::string& preheader, const std::string& body_inner) {
    return
        R"(<!DOCTYPE html><html lang="en"><head>)"
        R"(<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">)"
        R"(<meta name="x-apple-disable-message-reformatting">)"
        R"(<title>Kallix SIEM</title></head>)"
        // Preheader text (shows in inbox preview, hidden in body)
        R"(<body style="margin:0;padding:0;background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">)"
        R"(<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;color:#f0f2f5;">)" + preheader + R"(</div>)"
        R"(<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f2f5;padding:0;">)"
        R"(<tr><td align="center" style="padding:40px 16px;">)"
        R"(<table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">)"
        // Top accent bar — brand color stripe like Huntress
        R"(<tr><td style="background:#1a1f2e;padding:0;height:5px;font-size:0;">&nbsp;</td></tr>)"
        // Header — logo area
        R"(<tr><td style="background:#1a1f2e;padding:28px 40px 24px;">)"
        R"(<table cellpadding="0" cellspacing="0" border="0" width="100%"><tr>)"
        R"(<td style="vertical-align:middle;">)"
        R"(<span style="font-size:22px;font-weight:800;color:#ffffff;letter-spacing:-0.5px;">)"
        R"(<span style="color:#00d4aa;">&#11835;</span> KALLIX</span>)"
        R"(<span style="font-size:11px;font-weight:600;color:#4ade80;letter-spacing:3px;text-transform:uppercase;margin-left:10px;vertical-align:middle;">SIEM</span>)"
        R"(</td>)"
        R"(<td align="right" style="vertical-align:middle;">)"
        R"(<span style="display:inline-block;background:rgba(0,212,170,0.15);color:#00d4aa;font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;padding:4px 10px;border-radius:4px;border:1px solid rgba(0,212,170,0.3);">Security Alert</span>)"
        R"(</td></tr></table>)"
        R"(</td></tr>)"
        // Body
        R"(<tr><td style="padding:36px 40px;">)" + body_inner +
        R"(</td></tr>)"
        // Divider
        R"(<tr><td style="padding:0 40px;"><div style="border-top:1px solid #e5e7eb;"></div></td></tr>)"
        // Footer
        R"(<tr><td style="padding:24px 40px;background:#f9fafb;">)"
        R"(<table cellpadding="0" cellspacing="0" border="0" width="100%"><tr>)"
        R"(<td style="font-size:11px;color:#9ca3af;line-height:1.7;">)"
        R"(This is an automated security notification from <strong>Kallix SIEM</strong>.<br>)"
        R"(Do not reply to this email. If you have concerns, contact your system administrator.)"
        R"(</td>)"
        R"(<td align="right" style="vertical-align:top;">)"
        R"(<span style="font-size:10px;color:#d1d5db;font-weight:600;letter-spacing:1px;text-transform:uppercase;">KALLIX SIEM</span>)"
        R"(</td></tr></table>)"
        R"(</td></tr>)"
        R"(</table>)"
        R"(</td></tr></table>)"
        R"(</body></html>)";
}

static std::string onboarding_email_html(const std::string& first_name,
                                          const std::string& email,
                                          const std::string& temp_pass,
                                          const std::string& base_url) {
    std::string preheader = "Your Kallix SIEM account is ready. Sign in with your temporary credentials.";
    std::string body =
        // Greeting
        R"(<h1 style="margin:0 0 6px;font-size:26px;font-weight:800;color:#111827;letter-spacing:-0.5px;">Welcome to Kallix SIEM</h1>)"
        R"(<p style="margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.7;">Hi )" + first_name + R"(, your account has been provisioned. Use the credentials below to sign in for the first time.</p>)"

        // Credentials card
        R"(<div style="background:#111827;border-radius:8px;padding:24px 28px;margin-bottom:28px;">)"
        R"(<div style="margin-bottom:20px;">)"
        R"(<div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#6b7280;margin-bottom:6px;">Login Email</div>)"
        R"(<div style="font-size:16px;font-weight:600;color:#f9fafb;">)" + email + R"(</div>)"
        R"(</div>)"
        R"(<div style="border-top:1px solid #1f2937;padding-top:20px;">)"
        R"(<div style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#6b7280;margin-bottom:8px;">Temporary Password</div>)"
        R"(<div style="display:inline-block;background:#0d1117;border:1px solid #374151;border-radius:6px;padding:10px 18px;">)"
        R"(<span style="font-family:'Courier New',Courier,monospace;font-size:22px;font-weight:700;color:#00d4aa;letter-spacing:3px;">)" + temp_pass + R"(</span>)"
        R"(</div>)"
        R"(<div style="font-size:11px;color:#6b7280;margin-top:8px;">&#128274; Valid for one use only</div>)"
        R"(</div></div>)"

        // CTA button
        R"(<table cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;"><tr><td>)"
        R"(<a href=")" + base_url + R"(" style="display:inline-block;background:#00d4aa;color:#0d1117;text-decoration:none;font-size:15px;font-weight:700;padding:14px 32px;border-radius:6px;letter-spacing:0.3px;">)"
        R"(Sign In to Kallix SIEM &#8594;)"
        R"(</a></td></tr></table>)"

        // What to expect
        R"(<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-left:4px solid #22c55e;border-radius:0 6px 6px 0;padding:16px 20px;margin-bottom:20px;">)"
        R"(<div style="font-size:13px;font-weight:700;color:#15803d;margin-bottom:8px;">&#9989; Required on first login</div>)"
        R"(<ul style="margin:0;padding-left:20px;color:#166534;font-size:13px;line-height:2;">)"
        R"(<li>Set a new secure password</li>)"
        R"(<li>Enroll your authenticator app (MFA)</li>)"
        R"(</ul></div>)"

        // Security notice
        R"(<div style="background:#fefce8;border:1px solid #fde68a;border-radius:6px;padding:14px 18px;">)"
        R"(<div style="font-size:12px;color:#92400e;line-height:1.6;">)"
        R"(<strong>&#9888; Security notice:</strong> If you were not expecting this email, do not click any links and contact your IT administrator immediately.)"
        R"(</div></div>)";

    return html_shell(preheader, body);
}

static std::string admin_reset_email_html(const std::string& display_name,
                                           const std::string& reset_link) {
    std::string preheader = "A password reset has been initiated for your Kallix SIEM account.";
    std::string body =
        R"(<h1 style="margin:0 0 6px;font-size:26px;font-weight:800;color:#111827;letter-spacing:-0.5px;">Password Reset Request</h1>)"
        R"(<p style="margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.7;">Hi )" + display_name + R"(,<br>An administrator has initiated a password reset for your <strong>Kallix SIEM</strong> account.</p>)"

        R"(<table cellpadding="0" cellspacing="0" border="0" style="margin-bottom:28px;"><tr><td>)"
        R"(<a href=")" + reset_link + R"(" style="display:inline-block;background:#00d4aa;color:#0d1117;text-decoration:none;font-size:15px;font-weight:700;padding:14px 32px;border-radius:6px;">)"
        R"(Reset My Password &#8594;)"
        R"(</a></td></tr></table>)"

        R"(<div style="background:#fff7ed;border:1px solid #fed7aa;border-left:4px solid #f97316;border-radius:0 6px 6px 0;padding:14px 18px;margin-bottom:20px;">)"
        R"(<div style="font-size:13px;font-weight:700;color:#c2410c;margin-bottom:6px;">&#9201; This link expires in 1 hour</div>)"
        R"(<div style="font-size:12px;color:#7c2d12;margin-bottom:8px;">If the button above doesn't work, copy and paste this URL:</div>)"
        R"(<div style="font-family:'Courier New',Courier,monospace;font-size:11px;color:#6366f1;word-break:break-all;background:#fff;border:1px solid #e5e7eb;border-radius:4px;padding:8px 10px;">)" + reset_link + R"(</div>)"
        R"(</div>)"

        R"(<div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:14px 18px;">)"
        R"(<div style="font-size:12px;color:#6b7280;line-height:1.6;">)"
        R"(If you did not request this reset, your password has not been changed. Contact your administrator if you believe this was unauthorized.)"
        R"(</div></div>)";

    return html_shell(preheader, body);
}

void ApiServer::register_user_routes() {

    // ── List users ──
    server_.Get("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        auto users = storage_.list_users();
        nlohmann::json arr = nlohmann::json::array();
        for (auto& u : users) {
            arr.push_back({
                {"user_id",    u.user_id},
                {"username",   u.username},
                {"email",      u.email},
                {"first_name", u.first_name},
                {"last_name",  u.last_name},
                {"role",       u.role},
                {"created_at", u.created_at},
                {"mfa_enabled", u.mfa_enabled}
            });
        }
        res.set_content(arr.dump(), "application/json");
    });

    // ── Create user (admin) ──
    // Accepts: email (login identity), first_name, last_name, role
    // Auto-generates a temp password and emails it to the user.
    server_.Post("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string email      = body.value("email", "");
            std::string first_name = body.value("first_name", "");
            std::string last_name  = body.value("last_name", "");
            std::string role       = body.value("role", "analyst");

            if (email.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Email is required"})", "application/json");
                return;
            }
            if (first_name.empty() || last_name.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"First name and last name are required"})", "application/json");
                return;
            }
            if (email.size() > 255 || first_name.size() > 64 || last_name.size() > 64) {
                res.status = 400;
                res.set_content(R"({"error":"Input exceeds maximum length"})", "application/json");
                return;
            }
            if (role != "admin" && role != "analyst" && role != "viewer") {
                res.status = 400;
                res.set_content(R"({"error":"Role must be one of: admin, analyst, viewer"})", "application/json");
                return;
            }
            if (storage_.get_user_by_email(email)) {
                res.status = 409;
                res.set_content(R"({"error":"Email already in use"})", "application/json");
                return;
            }

            std::string temp_pass = generate_temp_password();
            auto salt = generate_salt();
            auto hash = hash_password(temp_pass, salt);
            auto uid  = generate_uuid();
            // username = email (login is by email; username used as unique key)
            if (!storage_.create_user(uid, email, email, first_name, last_name, hash, salt, role)) {
                res.status = 500;
                res.set_content(R"({"error":"Failed to create user"})", "application/json");
                return;
            }
            storage_.set_force_password_change(uid, true);

            if (smtp_config_.enabled) {
                std::string base_url = smtp_config_.base_url.empty() ? "https://kallix.cloud" : smtp_config_.base_url;
                std::string subject  = "Welcome to Kallix SIEM — Your Account Details";
                std::string plain    =
                    "Hello " + first_name + " " + last_name + ",\r\n\r\n"
                    "Your Kallix SIEM account is ready.\r\n\r\n"
                    "Login email:        " + email + "\r\n"
                    "Temporary password: " + temp_pass + "\r\n\r\n"
                    "Sign in at: " + base_url + "\r\n\r\n"
                    "On first login you will be required to set a new password and configure MFA.\r\n\r\n"
                    "-- Kallix SIEM\r\n";
                std::string html = onboarding_email_html(first_name, email, temp_pass, base_url);
                if (!send_email_html(smtp_config_, email, subject, plain, html)) {
                    LOG_WARN("POST /api/users: failed to send welcome email to {}", email);
                }
            } else {
                LOG_WARN("POST /api/users: SMTP not configured — welcome email not sent for {}", email);
            }

            nlohmann::json result = {
                {"user_id", uid}, {"email", email},
                {"first_name", first_name}, {"last_name", last_name}, {"role", role}
            };
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── Update user ──
    server_.Put("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string user_id    = body.value("user_id", "");
            std::string email      = body.value("email", "");
            std::string password   = body.value("password", "");
            std::string first_name = body.value("first_name", "");
            std::string last_name  = body.value("last_name", "");

            if (user_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"user_id required"})", "application/json");
                return;
            }

            if (body.contains("role")) {
                std::string role = body["role"].get<std::string>();
                if (role != "admin" && role != "analyst" && role != "viewer") {
                    res.status = 400;
                    res.set_content(R"({"error":"Role must be one of: admin, analyst, viewer"})", "application/json");
                    return;
                }
                storage_.update_user(user_id, email, role, first_name, last_name);
            }
            if (!password.empty()) {
                auto policy_err = validate_password_policy(password, auth_config_);
                if (!policy_err.empty()) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", policy_err}}).dump(), "application/json");
                    return;
                }
                auto salt = generate_salt();
                auto hash = hash_password(password, salt);
                storage_.update_user_password(user_id, hash, salt);
            }
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── Delete user ──
    server_.Delete("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session) return;
        if (session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
        std::string user_id = req.has_param("id") ? req.get_param_value("id") : "";
        if (user_id.empty()) {
            try {
                auto body = nlohmann::json::parse(req.body);
                user_id = body.value("user_id", "");
            } catch (const std::exception& e) {
                LOG_WARN("DELETE /api/users: failed to parse body: {}", e.what());
            }
        }
        if (user_id.empty()) {
            res.status = 400;
            res.set_content(R"({"error":"user_id required"})", "application/json");
            return;
        }
        if (user_id == session->user_id) {
            res.status = 400;
            res.set_content(R"({"error":"Cannot delete your own account"})", "application/json");
            return;
        }
        storage_.delete_user(user_id);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    // ── Admin: force logoff (kill all sessions) ──
    server_.Post("/api/users/force-logoff", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            if (user_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"user_id required"})", "application/json");
                return;
            }
            storage_.admin_force_logoff(user_id);
            LOG_INFO("Admin forced logoff for user_id={}", user_id);
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── Admin: force MFA re-registration ──
    server_.Post("/api/users/force-mfa-reset", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            if (user_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"user_id required"})", "application/json");
                return;
            }
            storage_.admin_force_mfa_reset(user_id);
            storage_.admin_force_logoff(user_id); // terminate existing sessions
            LOG_INFO("Admin forced MFA re-registration for user_id={}", user_id);
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // ── Admin: send password reset email ──
    server_.Post("/api/users/send-reset", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            if (user_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"user_id required"})", "application/json");
                return;
            }

            std::optional<PostgresStorageEngine::UserRecord> target;
            for (auto& u : storage_.list_users()) {
                if (u.user_id == user_id) { target = u; break; }
            }
            if (!target) {
                res.status = 404;
                res.set_content(R"({"error":"User not found"})", "application/json");
                return;
            }
            if (target->email.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"User has no email address on file"})", "application/json");
                return;
            }
            if (!smtp_config_.enabled) {
                res.status = 503;
                res.set_content(R"({"error":"SMTP is not configured — cannot send email"})", "application/json");
                return;
            }

            std::string token   = generate_session_token();
            int64_t expires     = now_ms() + (60LL * 60 * 1000); // 1 hour
            storage_.create_reset_token(sha256_hex(token), user_id, expires);
            storage_.cleanup_expired_reset_tokens();

            std::string base_url   = smtp_config_.base_url.empty() ? "http://localhost:5173" : smtp_config_.base_url;
            std::string reset_link = base_url + "/reset-password?token=" + token;
            std::string display    = target->first_name.empty()
                                     ? target->email
                                     : target->first_name + " " + target->last_name;

            std::string plain =
                "Hello " + display + ",\r\n\r\n"
                "An administrator has initiated a password reset for your Kallix SIEM account.\r\n\r\n"
                "Reset link (valid 1 hour):\r\n" + reset_link + "\r\n\r\n"
                "If you did not expect this, contact your administrator.\r\n\r\n"
                "-- Kallix SIEM\r\n";
            std::string html = admin_reset_email_html(display, reset_link);

            bool sent = send_email_html(smtp_config_, target->email, "Kallix SIEM — Password Reset", plain, html);
            if (!sent) {
                res.status = 502;
                res.set_content(R"({"error":"Failed to send email — check SMTP configuration"})", "application/json");
                return;
            }
            LOG_INFO("Admin sent password reset email to {} (user_id={})", target->email, user_id);
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });
}

} // namespace outpost
