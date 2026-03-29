// ApiServer — User management routes (admin-only CRUD)
// Split from server.cpp for maintainability

#include "api/server.h"
#include "common/utils.h"
#include "auth/auth.h"

#include <nlohmann/json.hpp>

namespace outpost {

static std::string extract_bearer_users(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return "";
    const auto& val = it->second;
    if (val.substr(0, 7) == "Bearer ") return val.substr(7);
    return "";
}

void ApiServer::register_user_routes() {

    server_.Get("/api/users", [this](const httplib::Request& req, httplib::Response& res) {
        auto token = extract_bearer_users(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
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
        auto token = extract_bearer_users(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
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
            if (password.size() < 4) {
                res.status = 400;
                res.set_content(R"({"error":"Password must be at least 4 characters"})", "application/json");
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
        auto token = extract_bearer_users(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
        try {
            auto body = nlohmann::json::parse(req.body);
            std::string user_id = body.value("user_id", "");
            std::string email   = body.value("email", "");
            std::string role    = body.value("role", "");
            std::string password = body.value("password", "");

            if (user_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"user_id required"})", "application/json");
                return;
            }

            if (!role.empty()) {
                storage_.update_user(user_id, email, role);
            }
            if (!password.empty()) {
                if (password.size() < 4) {
                    res.status = 400;
                    res.set_content(R"({"error":"Password must be at least 4 characters"})", "application/json");
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
        auto token = extract_bearer_users(req);
        auto session = storage_.validate_session(token);
        if (!session || session->role != "admin") {
            res.status = 403;
            res.set_content(R"({"error":"Admin access required"})", "application/json");
            return;
        }
        std::string user_id = req.has_param("id") ? req.get_param_value("id") : "";
        if (user_id.empty()) {
            try {
                auto body = nlohmann::json::parse(req.body);
                user_id = body.value("user_id", "");
            } catch (...) {}
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
