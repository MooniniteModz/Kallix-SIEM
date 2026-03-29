// PostgresStorageEngine — Alert storage methods
// Split from postgres_storage_engine.cpp for maintainability

#include "storage/postgres_storage_engine.h"
#include "rules/rule.h"
#include "common/utils.h"
#include "common/logger.h"

namespace outpost {

void PostgresStorageEngine::insert_alert(const Alert& alert) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return;

    const char* sql = "INSERT INTO alerts "
                      "(alert_id, rule_id, rule_name, severity, description, event_ids, created_at, acknowledged) "
                      "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
                      "ON CONFLICT (alert_id) DO NOTHING;";

    std::string severity_str = to_string(alert.severity);
    nlohmann::json ids_json = alert.event_ids;
    std::string ids_str = ids_json.dump();
    std::string created_at_str = std::to_string(alert.created_at);
    std::string acknowledged_str = std::to_string(alert.acknowledged ? 1 : 0);

    const char* params[] = {
        alert.alert_id.c_str(),
        alert.rule_id.c_str(),
        alert.rule_name.c_str(),
        severity_str.c_str(),
        alert.description.c_str(),
        ids_str.c_str(),
        created_at_str.c_str(),
        acknowledged_str.c_str()
    };

    PGresult* result = PQexecParams(conn_, sql, 8, nullptr, params, nullptr, nullptr, 0);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        LOG_WARN("Failed to insert alert: {}", PQerrorMessage(conn_));
    }

    PQclear(result);
}

std::vector<Alert> PostgresStorageEngine::get_alerts(int limit) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<Alert> results;

    if (!conn_) return results;

    std::string sql = "SELECT alert_id, rule_id, rule_name, severity, description, "
                      "event_ids, created_at, acknowledged "
                      "FROM alerts ORDER BY created_at DESC LIMIT " + std::to_string(limit) + ";";

    PGresult* result = PQexec(conn_, sql.c_str());

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("get_alerts failed: {}", PQerrorMessage(conn_));
        PQclear(result);
        return results;
    }

    auto col_text = [&](int row, int col) -> std::string {
        if (PQgetisnull(result, row, col)) return "";
        const char* value = PQgetvalue(result, row, col);
        return value ? std::string(value) : "";
    };

    int num_rows = PQntuples(result);
    for (int i = 0; i < num_rows; ++i) {
        Alert a;
        a.alert_id     = col_text(i, 0);
        a.rule_id      = col_text(i, 1);
        a.rule_name    = col_text(i, 2);
        a.severity     = rule_severity_from_string(col_text(i, 3));
        a.description  = col_text(i, 4);

        std::string ids = col_text(i, 5);
        if (!ids.empty()) {
            try {
                auto j = nlohmann::json::parse(ids);
                if (j.is_array()) {
                    for (const auto& id : j) {
                        a.event_ids.push_back(id.get<std::string>());
                    }
                }
            } catch (...) {}
        }

        a.created_at   = std::stoll(col_text(i, 6));
        a.acknowledged = std::stoi(col_text(i, 7)) != 0;

        results.push_back(std::move(a));
    }

    PQclear(result);
    return results;
}

bool PostgresStorageEngine::update_alert_status(const std::string& alert_id, const std::string& status) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    std::string sql;
    if (status == "acknowledged") {
        sql = "UPDATE alerts SET acknowledged = 1, status = 'acknowledged' WHERE alert_id = $1;";
    } else if (status == "closed") {
        sql = "UPDATE alerts SET status = 'closed' WHERE alert_id = $1;";
    } else {
        sql = "UPDATE alerts SET status = $2 WHERE alert_id = $1;";
    }

    if (status == "acknowledged" || status == "closed") {
        const char* params[] = { alert_id.c_str() };
        PGresult* result = PQexecParams(conn_, sql.c_str(), 1, nullptr, params, nullptr, nullptr, 0);
        bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
        PQclear(result);
        return ok;
    } else {
        const char* params[] = { alert_id.c_str(), status.c_str() };
        PGresult* result = PQexecParams(conn_, sql.c_str(), 2, nullptr, params, nullptr, nullptr, 0);
        bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
        PQclear(result);
        return ok;
    }
}

int64_t PostgresStorageEngine::alert_count() const {
    if (!conn_) return 0;

    auto* self = const_cast<PostgresStorageEngine*>(this);

    PGresult* result = PQexec(self->conn_, "SELECT COUNT(*) FROM alerts;");

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("alert_count failed: {}", PQerrorMessage(self->conn_));
        PQclear(result);
        return 0;
    }

    int64_t count = std::stoll(PQgetvalue(result, 0, 0));
    PQclear(result);
    return count;
}

} // namespace outpost
