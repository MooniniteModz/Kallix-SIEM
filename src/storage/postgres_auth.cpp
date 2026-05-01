// PostgresStorageEngine — User and session management methods
// Split from postgres_storage_engine.cpp for maintainability

#include "storage/postgres_storage_engine.h"
#include "common/utils.h"
#include "common/logger.h"

namespace outpost {

bool PostgresStorageEngine::create_user(const std::string& user_id,
                                         const std::string& username,
                                         const std::string& email,
                                         const std::string& first_name,
                                         const std::string& last_name,
                                         const std::string& password_hash,
                                         const std::string& salt,
                                         const std::string& role) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "INSERT INTO users (user_id, username, email, first_name, last_name, password_hash, salt, role, created_at) "
                      "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (username) DO NOTHING;";
    std::string ts = std::to_string(now_ms());
    const char* params[] = { user_id.c_str(), username.c_str(), email.c_str(),
                             first_name.c_str(), last_name.c_str(),
                             password_hash.c_str(), salt.c_str(),
                             role.c_str(), ts.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 9, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) LOG_WARN("create_user failed: {}", PQerrorMessage(conn_));
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::update_user(const std::string& user_id,
                                         const std::string& email,
                                         const std::string& role,
                                         const std::string& first_name,
                                         const std::string& last_name) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "UPDATE users SET email = $2, role = $3, first_name = $4, last_name = $5 WHERE user_id = $1;";
    const char* params[] = { user_id.c_str(), email.c_str(), role.c_str(), first_name.c_str(), last_name.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 5, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::update_user_password(const std::string& user_id,
                                                  const std::string& password_hash,
                                                  const std::string& salt) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "UPDATE users SET password_hash = $2, salt = $3 WHERE user_id = $1;";
    const char* params[] = { user_id.c_str(), password_hash.c_str(), salt.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 3, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::delete_user(const std::string& user_id) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql1 = "DELETE FROM sessions WHERE user_id = $1;";
    const char* params[] = { user_id.c_str() };
    PGresult* r1 = PQexecParams(conn_, sql1, 1, nullptr, params, nullptr, nullptr, 0);
    PQclear(r1);

    const char* sql2 = "DELETE FROM users WHERE user_id = $1;";
    PGresult* r2 = PQexecParams(conn_, sql2, 1, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r2) == PGRES_COMMAND_OK;
    PQclear(r2);
    return ok;
}

static bool pg_bool(PGresult* r, int row, int col) {
    if (PQnfields(r) <= col) return false;
    std::string v = PQgetvalue(r, row, col);
    return (v == "t" || v == "true" || v == "1");
}

static PostgresStorageEngine::UserRecord row_to_user(PGresult* result, int row) {
    PostgresStorageEngine::UserRecord rec;
    rec.user_id                = PQgetvalue(result, row, 0);
    rec.username               = PQgetvalue(result, row, 1);
    rec.email                  = PQgetvalue(result, row, 2);
    rec.password_hash          = PQgetvalue(result, row, 3);
    rec.salt                   = PQgetvalue(result, row, 4);
    rec.role                   = PQgetvalue(result, row, 5);
    rec.created_at             = std::stoll(PQgetvalue(result, row, 6));
    rec.mfa_enabled            = pg_bool(result, row, 7);
    if (PQnfields(result) > 8)  rec.totp_secret            = PQgetvalue(result, row, 8);
    if (PQnfields(result) > 9)  rec.backup_codes           = PQgetvalue(result, row, 9);
    if (PQnfields(result) > 10) rec.force_password_change  = pg_bool(result, row, 10);
    if (PQnfields(result) > 11) rec.first_name             = PQgetvalue(result, row, 11);
    if (PQnfields(result) > 12) rec.last_name              = PQgetvalue(result, row, 12);
    return rec;
}

std::optional<PostgresStorageEngine::UserRecord>
PostgresStorageEngine::get_user_by_username(const std::string& username) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return std::nullopt;

    const char* sql = "SELECT user_id, username, email, password_hash, salt, role, created_at, mfa_enabled, totp_secret, backup_codes, force_password_change, first_name, last_name FROM users WHERE username = $1;";
    const char* params[] = { username.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) == 0) {
        PQclear(result);
        return std::nullopt;
    }

    auto rec = row_to_user(result, 0);
    PQclear(result);
    return rec;
}

std::optional<PostgresStorageEngine::UserRecord>
PostgresStorageEngine::get_user_by_email(const std::string& email) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return std::nullopt;

    const char* sql = "SELECT user_id, username, email, password_hash, salt, role, created_at, mfa_enabled, totp_secret, backup_codes, force_password_change, first_name, last_name FROM users WHERE email = $1;";
    const char* params[] = { email.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) == 0) {
        PQclear(result);
        return std::nullopt;
    }

    auto rec = row_to_user(result, 0);
    PQclear(result);
    return rec;
}

std::vector<PostgresStorageEngine::UserRecord>
PostgresStorageEngine::list_users() {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<UserRecord> users;
    if (!conn_) return users;

    PGresult* result = PQexec(conn_, "SELECT user_id, username, email, password_hash, salt, role, created_at, mfa_enabled, totp_secret, backup_codes, force_password_change, first_name, last_name FROM users ORDER BY created_at;");
    if (PQresultStatus(result) != PGRES_TUPLES_OK) { PQclear(result); return users; }

    int rows = PQntuples(result);
    for (int i = 0; i < rows; ++i) {
        users.push_back(row_to_user(result, i));
    }
    PQclear(result);
    return users;
}

int PostgresStorageEngine::user_count() {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return 0;

    PGresult* result = PQexec(conn_, "SELECT COUNT(*) FROM users;");
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        PQclear(result);
        return 0;
    }
    int count = std::stoi(PQgetvalue(result, 0, 0));
    PQclear(result);
    return count;
}

bool PostgresStorageEngine::create_session(const std::string& token,
                                            const std::string& user_id,
                                            int64_t created_at,
                                            int64_t expires_at) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "INSERT INTO sessions (token, user_id, created_at, expires_at) "
                      "VALUES ($1, $2, $3, $4);";
    std::string ca = std::to_string(created_at);
    std::string ea = std::to_string(expires_at);
    const char* params[] = { token.c_str(), user_id.c_str(), ca.c_str(), ea.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 4, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

std::optional<PostgresStorageEngine::SessionInfo>
PostgresStorageEngine::validate_session(const std::string& token) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return std::nullopt;

    std::string now = std::to_string(now_ms());
    const char* sql = "SELECT s.user_id, u.username, u.email, u.role "
                      "FROM sessions s JOIN users u ON s.user_id = u.user_id "
                      "WHERE s.token = $1 AND s.expires_at > $2;";
    const char* params[] = { token.c_str(), now.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 2, nullptr, params, nullptr, nullptr, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) == 0) {
        PQclear(result);
        return std::nullopt;
    }

    SessionInfo info;
    info.user_id  = PQgetvalue(result, 0, 0);
    info.username = PQgetvalue(result, 0, 1);
    info.email    = PQgetvalue(result, 0, 2);
    info.role     = PQgetvalue(result, 0, 3);
    PQclear(result);
    return info;
}

bool PostgresStorageEngine::delete_sessions_for_user(const std::string& user_id) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "DELETE FROM sessions WHERE user_id = $1;";
    const char* params[] = { user_id.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::delete_session(const std::string& token) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "DELETE FROM sessions WHERE token = $1;";
    const char* params[] = { token.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

void PostgresStorageEngine::cleanup_expired_sessions() {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return;

    std::string now = std::to_string(now_ms());
    const char* sql = "DELETE FROM sessions WHERE expires_at <= $1;";
    const char* params[] = { now.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);
    if (PQresultStatus(result) == PGRES_COMMAND_OK) {
        int deleted = std::atoi(PQcmdTuples(result));
        if (deleted > 0) {
            LOG_DEBUG("Cleaned up {} expired sessions", deleted);
        }
    }
    PQclear(result);
}

bool PostgresStorageEngine::set_user_totp(const std::string& user_id, const std::string& secret) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return false;
    const char* sql = "UPDATE users SET totp_secret = $2 WHERE user_id = $1;";
    const char* p[] = { user_id.c_str(), secret.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 2, nullptr, p, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok;
}

bool PostgresStorageEngine::enable_user_mfa(const std::string& user_id, const std::string& backup_codes_json) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return false;
    const char* sql = "UPDATE users SET mfa_enabled = TRUE, backup_codes = $2 WHERE user_id = $1;";
    const char* p[] = { user_id.c_str(), backup_codes_json.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 2, nullptr, p, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok;
}

bool PostgresStorageEngine::disable_user_mfa(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return false;
    const char* sql = "UPDATE users SET mfa_enabled = FALSE, totp_secret = '', backup_codes = '[]' WHERE user_id = $1;";
    const char* p[] = { user_id.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 1, nullptr, p, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok;
}

bool PostgresStorageEngine::update_backup_codes(const std::string& user_id, const std::string& backup_codes_json) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return false;
    const char* sql = "UPDATE users SET backup_codes = $2 WHERE user_id = $1;";
    const char* p[] = { user_id.c_str(), backup_codes_json.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 2, nullptr, p, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok;
}

bool PostgresStorageEngine::create_pending_mfa(const std::string& token,
                                                const std::string& user_id,
                                                int64_t expires_at) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return false;
    const char* sql = "INSERT INTO pending_mfa (token, user_id, expires_at) VALUES ($1, $2, $3);";
    std::string ea = std::to_string(expires_at);
    const char* p[] = { token.c_str(), user_id.c_str(), ea.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 3, nullptr, p, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok;
}

bool PostgresStorageEngine::set_force_password_change(const std::string& user_id, bool value) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return false;
    const char* val = value ? "true" : "false";
    const char* sql = "UPDATE users SET force_password_change = $2 WHERE user_id = $1;";
    const char* p[] = { user_id.c_str(), val };
    PGresult* r = PQexecParams(conn_, sql, 2, nullptr, p, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok;
}

bool PostgresStorageEngine::create_pending_change(const std::string& token,
                                                    const std::string& user_id,
                                                    int64_t expires_at) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return false;
    std::string exp = std::to_string(expires_at);
    const char* sql = "INSERT INTO pending_password_change (token, user_id, expires_at) VALUES ($1, $2, $3);";
    const char* p[] = { token.c_str(), user_id.c_str(), exp.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 3, nullptr, p, nullptr, nullptr, 0);
    bool ok = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    return ok;
}

std::optional<std::string> PostgresStorageEngine::consume_pending_change(const std::string& token) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return std::nullopt;
    std::string now = std::to_string(now_ms());
    const char* sql = "DELETE FROM pending_password_change WHERE token = $1 AND expires_at > $2 RETURNING user_id;";
    const char* p[] = { token.c_str(), now.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 2, nullptr, p, nullptr, nullptr, 0);
    std::optional<std::string> result;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0)
        result = PQgetvalue(r, 0, 0);
    PQclear(r);
    return result;
}

std::optional<std::string> PostgresStorageEngine::peek_pending_mfa(const std::string& token) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return std::nullopt;
    std::string now = std::to_string(now_ms());
    const char* sql = "SELECT user_id FROM pending_mfa WHERE token = $1 AND expires_at > $2;";
    const char* p[] = { token.c_str(), now.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 2, nullptr, p, nullptr, nullptr, 0);
    std::optional<std::string> result;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0)
        result = PQgetvalue(r, 0, 0);
    PQclear(r);
    return result;
}

std::optional<std::string> PostgresStorageEngine::consume_pending_mfa(const std::string& token) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!conn_) return std::nullopt;
    std::string now = std::to_string(now_ms());
    const char* sql = "DELETE FROM pending_mfa WHERE token = $1 AND expires_at > $2 RETURNING user_id;";
    const char* p[] = { token.c_str(), now.c_str() };
    PGresult* r = PQexecParams(conn_, sql, 2, nullptr, p, nullptr, nullptr, 0);
    std::optional<std::string> result;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0)
        result = PQgetvalue(r, 0, 0);
    PQclear(r);
    return result;
}

bool PostgresStorageEngine::admin_force_logoff(const std::string& user_id) {
    return delete_sessions_for_user(user_id);
}

bool PostgresStorageEngine::admin_force_mfa_reset(const std::string& user_id) {
    return disable_user_mfa(user_id);
}

} // namespace outpost
