// PostgresStorageEngine — Connector CRUD methods

#include "storage/postgres_storage_engine.h"
#include "common/logger.h"

namespace outpost {

std::vector<PostgresStorageEngine::ConnectorRecord> PostgresStorageEngine::get_connectors() {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<ConnectorRecord> results;
    if (!conn_) return results;

    PGresult* result = PQexec(conn_,
        "SELECT connector_id, name, type, enabled, settings::text, status, event_count, "
        "created_at, updated_at FROM connectors ORDER BY created_at DESC;");

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        PQclear(result);
        return results;
    }

    int rows = PQntuples(result);
    for (int i = 0; i < rows; ++i) {
        ConnectorRecord c;
        c.id            = PQgetvalue(result, i, 0);
        c.name          = PQgetvalue(result, i, 1);
        c.type          = PQgetvalue(result, i, 2);
        c.enabled       = std::string(PQgetvalue(result, i, 3)) == "1";
        c.settings_json = PQgetisnull(result, i, 4) ? "{}" : PQgetvalue(result, i, 4);
        c.status        = PQgetvalue(result, i, 5);
        c.event_count   = std::stoll(PQgetvalue(result, i, 6));
        c.created_at    = std::stoll(PQgetvalue(result, i, 7));
        c.updated_at    = std::stoll(PQgetvalue(result, i, 8));
        results.push_back(std::move(c));
    }

    PQclear(result);
    return results;
}

std::optional<PostgresStorageEngine::ConnectorRecord>
PostgresStorageEngine::get_connector(const std::string& id) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return std::nullopt;

    const char* sql = "SELECT connector_id, name, type, enabled, settings::text, status, "
                      "event_count, created_at, updated_at FROM connectors WHERE connector_id = $1;";
    const char* params[] = { id.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) == 0) {
        PQclear(result);
        return std::nullopt;
    }

    ConnectorRecord c;
    c.id            = PQgetvalue(result, 0, 0);
    c.name          = PQgetvalue(result, 0, 1);
    c.type          = PQgetvalue(result, 0, 2);
    c.enabled       = std::string(PQgetvalue(result, 0, 3)) == "1";
    c.settings_json = PQgetisnull(result, 0, 4) ? "{}" : PQgetvalue(result, 0, 4);
    c.status        = PQgetvalue(result, 0, 5);
    c.event_count   = std::stoll(PQgetvalue(result, 0, 6));
    c.created_at    = std::stoll(PQgetvalue(result, 0, 7));
    c.updated_at    = std::stoll(PQgetvalue(result, 0, 8));
    PQclear(result);
    return c;
}

bool PostgresStorageEngine::save_connector(const ConnectorRecord& c) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "INSERT INTO connectors "
                      "(connector_id, name, type, enabled, settings, status, event_count, created_at, updated_at) "
                      "VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9);";
    std::string en = c.enabled ? "1" : "0";
    std::string ec = std::to_string(c.event_count);
    std::string ca = std::to_string(c.created_at);
    std::string ua = std::to_string(c.updated_at);
    const char* params[] = { c.id.c_str(), c.name.c_str(), c.type.c_str(),
                             en.c_str(), c.settings_json.c_str(), c.status.c_str(),
                             ec.c_str(), ca.c_str(), ua.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 9, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) LOG_WARN("save_connector failed: {}", PQerrorMessage(conn_));
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::update_connector(const ConnectorRecord& c) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "UPDATE connectors SET name=$2, type=$3, enabled=$4, settings=$5::jsonb, "
                      "status=$6, event_count=$7, updated_at=$8 WHERE connector_id=$1;";
    std::string en = c.enabled ? "1" : "0";
    std::string ec = std::to_string(c.event_count);
    std::string ua = std::to_string(c.updated_at);
    const char* params[] = { c.id.c_str(), c.name.c_str(), c.type.c_str(),
                             en.c_str(), c.settings_json.c_str(), c.status.c_str(),
                             ec.c_str(), ua.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 8, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) LOG_WARN("update_connector failed: {}", PQerrorMessage(conn_));
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::delete_connector(const std::string& id) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "DELETE FROM connectors WHERE connector_id = $1;";
    const char* params[] = { id.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

int64_t PostgresStorageEngine::delete_events_by_source(const std::string& source_label) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_ || source_label.empty()) return 0;

    const char* sql = "DELETE FROM events WHERE source_type = $1;";
    const char* params[] = { source_label.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);

    int64_t deleted = 0;
    if (PQresultStatus(result) == PGRES_COMMAND_OK) {
        const char* tag = PQcmdTuples(result);
        if (tag && tag[0] != '\0') deleted = std::stoll(tag);
        LOG_INFO("Deleted {} events for source '{}'", deleted, source_label);
    } else {
        LOG_WARN("delete_events_by_source failed for '{}': {}", source_label, PQerrorMessage(conn_));
    }
    PQclear(result);
    
    return deleted;
}

} // namespace outpost