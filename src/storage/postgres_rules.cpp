// PostgresStorageEngine — Custom rules storage methods
// Split from postgres_storage_engine.cpp for maintainability

#include "storage/postgres_storage_engine.h"
#include "common/logger.h"

namespace outpost {

std::vector<PostgresStorageEngine::CustomRuleRecord> PostgresStorageEngine::get_custom_rules() {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<CustomRuleRecord> rules;
    if (!conn_) return rules;

    PGresult* result = PQexec(conn_,
        "SELECT rule_id, name, description, severity, type, source_type, category, action, "
        "field_match, field_value, config_json, tags_json, enabled, created_at, updated_at "
        "FROM custom_rules ORDER BY created_at;");
    if (PQresultStatus(result) != PGRES_TUPLES_OK) { PQclear(result); return rules; }

    int rows = PQntuples(result);
    for (int i = 0; i < rows; ++i) {
        CustomRuleRecord r;
        r.id          = PQgetvalue(result, i, 0);
        r.name        = PQgetvalue(result, i, 1);
        r.description = PQgetvalue(result, i, 2);
        r.severity    = PQgetvalue(result, i, 3);
        r.type        = PQgetvalue(result, i, 4);
        r.source_type = PQgetvalue(result, i, 5);
        r.category    = PQgetvalue(result, i, 6);
        r.action      = PQgetvalue(result, i, 7);
        r.field_match = PQgetvalue(result, i, 8);
        r.field_value = PQgetvalue(result, i, 9);
        r.config_json = PQgetvalue(result, i, 10);
        r.tags_json   = PQgetvalue(result, i, 11);
        r.enabled     = std::string(PQgetvalue(result, i, 12)) == "1";
        r.created_at  = std::stoll(PQgetvalue(result, i, 13));
        r.updated_at  = std::stoll(PQgetvalue(result, i, 14));
        rules.push_back(r);
    }
    PQclear(result);
    return rules;
}

bool PostgresStorageEngine::save_custom_rule(const CustomRuleRecord& r) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "INSERT INTO custom_rules "
        "(rule_id, name, description, severity, type, source_type, category, action, "
        "field_match, field_value, config_json, tags_json, enabled, created_at, updated_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15);";
    std::string en = r.enabled ? "1" : "0";
    std::string ca = std::to_string(r.created_at);
    std::string ua = std::to_string(r.updated_at);
    const char* params[] = {
        r.id.c_str(), r.name.c_str(), r.description.c_str(), r.severity.c_str(), r.type.c_str(),
        r.source_type.c_str(), r.category.c_str(), r.action.c_str(),
        r.field_match.c_str(), r.field_value.c_str(), r.config_json.c_str(), r.tags_json.c_str(),
        en.c_str(), ca.c_str(), ua.c_str()
    };
    PGresult* result = PQexecParams(conn_, sql, 15, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) LOG_WARN("save_custom_rule failed: {}", PQerrorMessage(conn_));
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::update_custom_rule(const CustomRuleRecord& r) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "UPDATE custom_rules SET "
        "name=$2, description=$3, severity=$4, type=$5, source_type=$6, category=$7, action=$8, "
        "field_match=$9, field_value=$10, config_json=$11, tags_json=$12, enabled=$13, updated_at=$14 "
        "WHERE rule_id=$1;";
    std::string en = r.enabled ? "1" : "0";
    std::string ua = std::to_string(r.updated_at);
    const char* params[] = {
        r.id.c_str(), r.name.c_str(), r.description.c_str(), r.severity.c_str(), r.type.c_str(),
        r.source_type.c_str(), r.category.c_str(), r.action.c_str(),
        r.field_match.c_str(), r.field_value.c_str(), r.config_json.c_str(), r.tags_json.c_str(),
        en.c_str(), ua.c_str()
    };
    PGresult* result = PQexecParams(conn_, sql, 14, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::delete_custom_rule(const std::string& id) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "DELETE FROM custom_rules WHERE rule_id = $1;";
    const char* params[] = { id.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

} // namespace outpost
