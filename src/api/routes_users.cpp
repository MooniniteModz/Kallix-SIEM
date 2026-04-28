// ApiServer — User management routes (admin-only CRUD)

#include "api/server.h"
#include "common/utils.h"
#include "auth/auth.h"

#include <nlohmann/json.hpp>

namespace outpost {

void ApiServer::register_user_routes() {

    server_.Get("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        auto users = storage_.list_users();
        nlohmann::json arr = nlohmann::json::array();
        for (auto& u : users) {
            arr.push_back({
                {"user_id", u.user_id}, {"username", u.username},
                {"email", u.email}, {"role", u.role}, {"created_at", u.created_at}
            });
        }
        res.set_content(arr.dump(), "application/json");
    });

    server_.Post("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string username = body.value("username", "");
            std::string email    = body.value("email", "");
            std::string password = body.value("password", "");
            std::string role     = body.value("role", "analyst");

            if (username.empty() || password.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"Username and password required"})", "application/json");
                return;
            }
            if (username.size() > 64 || email.size() > 255) {
                res.status = 400;
                res.set_content(R"({"error":"Username or email exceeds maximum length"})", "application/json");
                return;
            }
            if (role != "admin" && role != "analyst" && role != "viewer") {
                res.status = 400;
                res.set_content(R"({"error":"Role must be one of: admin, analyst, viewer"})", "application/json");
                return;
            }
            auto policy_err = validate_password_policy(password, auth_config_);
            if (!policy_err.empty()) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", policy_err}}).dump(), "application/json");
                return;
            }
            if (storage_.get_user_by_username(username)) {
                res.status = 409;
                res.set_content(R"({"error":"Username already exists"})", "application/json");
                return;
            }
            if (!email.empty() && storage_.get_user_by_email(email)) {
                res.status = 409;
                res.set_content(R"({"error":"Email already in use"})", "application/json");
                return;
            }

            auto salt = generate_salt();
            auto hash = hash_password(password, salt);
            auto uid  = generate_uuid();
            if (!storage_.create_user(uid, username, email, hash, salt, role)) {
                res.status = 500;
                res.set_content(R"({"error":"Failed to create user"})", "application/json");
                return;
            }
            nlohmann::json result = {{"user_id", uid}, {"username", username}, {"email", email}, {"role", role}};
            res.set_content(result.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    server_.Put("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        if (!require_admin(req, res)) return;
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string user_id  = body.value("user_id", "");
            std::string email    = body.value("email", "");
            std::string password = body.value("password", "");

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
                storage_.update_user(user_id, email, role);
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
}

} // namespace outpost
