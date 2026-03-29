// ApiServer — Auth routes (login, logout, session)
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/utils.h"
#include "common/logger.h"
#include "auth/auth.h"

#include <nlohmann/json.hpp>

namespace outpost {

static std::string extract_bearer_auth(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return "";
    const auto& val = it->second;
    if (val.substr(0, 7) == "Bearer ") return val.substr(7);
    return "";
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

            auto user = storage_.get_user_by_username(username);
            if (!user || !verify_password(password, user->salt, user->password_hash)) {
                res.status = 401;
                res.set_content(R"({"error":"Invalid username or password"})", "application/json");
                return;
            }

            auto token = generate_session_token();
            int64_t now = now_ms();
            int64_t expires = now + (static_cast<int64_t>(auth_config_.session_ttl_hours) * 3600 * 1000);
            storage_.create_session(token, user->user_id, now, expires);

            nlohmann::json result = {
                {"token", token},
                {"expires_at", expires},
                {"username", username},
                {"email", user->email},
                {"role", user->role}
            };
            res.set_content(result.dump(), "application/json");

        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Post("/api/auth/logout", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = extract_bearer_auth(req);
        if (!token.empty()) storage_.delete_session(token);
        res.set_content(R"({"status":"ok"})", "application/json");
    });

    server_.Get("/api/auth/me", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = extract_bearer_auth(req);
        auto session = storage_.validate_session(token);
        if (!session) {
            res.status = 401;
            res.set_content(R"({"error":"Not authenticated"})", "application/json");
            return;
        }
        nlohmann::json result = {
            {"username", session->username},
            {"email", session->email},
            {"role", session->role},
            {"user_id", session->user_id}
        };
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace outpost
