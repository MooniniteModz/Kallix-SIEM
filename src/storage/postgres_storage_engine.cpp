#include "storage/postgres_storage_engine.h"
#include "rules/rule.h"
#include "common/utils.h"
#include "common/logger.h"

#include <sstream>
#include <cstring>

namespace outpost {

// ═══════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR & DESTRUCTOR
// ═══════════════════════════════════════════════════════════════════════════

PostgresStorageEngine::PostgresStorageEngine(const PostgresConfig& config)
    : config_(config) {
    // Note: Connection is NOT opened here
    // This is good C++ practice: constructors should be lightweight
    // Heavy initialization happens in init()
}

PostgresStorageEngine::~PostgresStorageEngine() {
    // Destructor: cleanup when object is destroyed
    flush();  // Save any buffered events

    if (conn_) {
        PQfinish(conn_);  // Close PostgreSQL connection
        conn_ = nullptr;
    }

    LOG_INFO("PostgresStorageEngine destroyed");
}

// ═══════════════════════════════════════════════════════════════════════════
// INITIALIZATION: CONNECTION AND SCHEMA
// ═══════════════════════════════════════════════════════════════════════════

bool PostgresStorageEngine::init() {
    // Step 1: Build connection string
    // This string tells libpq how to connect to PostgreSQL
    // Try to use both TCP and Unix socket paths for flexibility
    std::stringstream conn_str;
    conn_str << "host=" << config_.host
             << " port=" << config_.port
             << " dbname=" << config_.dbname
             << " user=" << config_.user
             << " connect_timeout=5";  // 5 second timeout

    if (!config_.password.empty()) {
        conn_str << " password=" << config_.password;
    }

    // Also try the Unix socket as a fallback
    // This helps with peer authentication on local systems
    conn_str << " fallback_application_name=outpost";
    conn_str << " sslmode=disable";

    // Step 2: Open connection
    conn_ = PQconnectdb(conn_str.str().c_str());

    // Step 3: Check if connection succeeded
    if (PQstatus(conn_) != CONNECTION_OK) {
        LOG_ERROR("PostgreSQL connection failed: {}",
                  PQerrorMessage(conn_));
        PQfinish(conn_);
        conn_ = nullptr;
        return false;
    }

    LOG_INFO("Connected to PostgreSQL at {}:{}/{}",
             config_.host, config_.port, config_.dbname);

    // Step 4: Reserve space in write buffer (optimization)
    write_buffer_.reserve(config_.batch_size);

    // Step 5: Create tables (schema)
    // The CREATE TABLE IF NOT EXISTS is important: it doesn't fail if table exists
    const char* create_tables_sql = R"(
        CREATE TABLE IF NOT EXISTS events (
            event_id    TEXT PRIMARY KEY,
            timestamp   BIGINT NOT NULL,
            received_at BIGINT NOT NULL,
            source_type TEXT NOT NULL,
            source_host TEXT,
            severity    TEXT,
            category    TEXT,
            action      TEXT,
            outcome     TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            user_name   TEXT,
            user_agent  TEXT,
            resource    TEXT,
            raw         TEXT,
            metadata    JSONB
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type);
        CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_name);
        CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

        -- Full-text search index on raw log
        CREATE INDEX IF NOT EXISTS idx_events_raw_fts
            ON events USING GIN (to_tsvector('english', raw));

        CREATE TABLE IF NOT EXISTS alerts (
            alert_id    TEXT PRIMARY KEY,
            rule_id     TEXT NOT NULL,
            rule_name   TEXT,
            severity    TEXT,
            description TEXT,
            event_ids   TEXT,
            created_at  BIGINT NOT NULL,
            acknowledged INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);

        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'open';

        CREATE TABLE IF NOT EXISTS users (
            user_id       TEXT PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE DEFAULT '',
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            role          TEXT DEFAULT 'admin',
            created_at    BIGINT NOT NULL
        );

        ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT UNIQUE DEFAULT '';

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connectors (
            connector_id TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            type         TEXT NOT NULL,
            enabled      INTEGER DEFAULT 0,
            settings     JSONB,
            status       TEXT DEFAULT 'stopped',
            event_count  BIGINT DEFAULT 0,
            created_at   BIGINT NOT NULL,
            updated_at   BIGINT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS custom_rules (
            rule_id      TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            description  TEXT DEFAULT '',
            severity     TEXT DEFAULT 'medium',
            type         TEXT DEFAULT 'threshold',
            source_type  TEXT DEFAULT '',
            category     TEXT DEFAULT '',
            action       TEXT DEFAULT '',
            field_match  TEXT DEFAULT '',
            field_value  TEXT DEFAULT '',
            config_json  TEXT DEFAULT '{}',
            tags_json    TEXT DEFAULT '[]',
            enabled      INTEGER DEFAULT 1,
            created_at   BIGINT NOT NULL,
            updated_at   BIGINT NOT NULL
        );
    )";

    PGresult* result = PQexec(conn_, create_tables_sql);
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        LOG_ERROR("Failed to create schema: {}",
                  PQerrorMessage(conn_));
        PQclear(result);
        return false;
    }

    PQclear(result);  // Free result memory

    LOG_INFO("PostgreSQL schema initialized. Batch size: {}, Flush interval: {}ms",
             config_.batch_size, config_.flush_interval_ms);

    // ── Data migration: reclassify misclassified events ──
    // Events from connectors may have been stored as "syslog" before the parser
    // hint system was fully working. Reclassify based on metadata/raw content.
    const char* reclassify_sql = R"(
        UPDATE events SET source_type = 'unifi', category = 'network'
        WHERE source_type = 'syslog'
        AND (
            metadata ? 'hardwareId' OR
            metadata ? 'firmwareVersion' OR
            metadata ? 'hardware_id' OR
            metadata ? 'device_type' OR
            (metadata ? 'mac' AND (metadata ? 'oui' OR metadata ? 'network_id' OR metadata ? 'usergroup_id')) OR
            (metadata ? 'site_id' AND (metadata ? 'purpose' OR metadata ? 'networkgroup' OR metadata ? 'dhcpd_enabled')) OR
            metadata ? 'siteId' OR
            raw LIKE '%"hardwareId"%' OR
            raw LIKE '%"firmwareVersion"%' OR
            raw LIKE '%"oui"%' OR
            raw LIKE '%"siteId"%' OR
            raw LIKE '%"site_id"%' OR
            raw LIKE '%"override_inform_host"%' OR
            raw LIKE '%"networkgroup"%' OR
            raw LIKE '%"release_channel"%' OR
            raw LIKE '%"usergroup_id"%' OR
            raw LIKE '%"network_id"%' OR
            raw LIKE '%"ipAddress"%' OR
            (raw LIKE '%"mac"%' AND raw LIKE '%"hostname"%') OR
            source_host ILIKE '%unifi%'
        );
    )";
    PGresult* mig_result = PQexec(conn_, reclassify_sql);
    if (PQresultStatus(mig_result) == PGRES_COMMAND_OK) {
        int rows = std::atoi(PQcmdTuples(mig_result));
        if (rows > 0) {
            LOG_INFO("Reclassified {} events from 'syslog' to 'unifi'", rows);
        }
    }
    PQclear(mig_result);

    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// BUFFERING: INSERT AND FLUSH
// ═══════════════════════════════════════════════════════════════════════════

void PostgresStorageEngine::insert(const Event& event) {
    // Lock the mutex to prevent race conditions
    // std::lock_guard is RAII: lock is held until scope ends
    std::lock_guard<std::mutex> lock(write_mutex_);

    // Add event to buffer
    write_buffer_.push_back(event);

    // Optional: flush if buffer is full (could add auto-flush here)
    // For now, we rely on the flush_worker thread
}

void PostgresStorageEngine::flush() {
    // Lock before accessing write_buffer_
    std::lock_guard<std::mutex> lock(write_mutex_);
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);

    if (write_buffer_.empty()) {
        return;  // Nothing to do
    }

    if (!conn_) {
        LOG_ERROR("No database connection available for flush");
        write_buffer_.clear();
        return;
    }

    // Step 1: Start transaction
    // Transactions group multiple queries: either all succeed or all fail
    PGresult* result = PQexec(conn_, "BEGIN;");
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        LOG_ERROR("Failed to begin transaction: {}",
                  PQerrorMessage(conn_));
        PQclear(result);
        return;
    }
    PQclear(result);

    // Step 2: Prepare the INSERT statement once
    // Prepared statements are more secure (prevent SQL injection)
    // and faster (query is parsed once, executed many times)
    const char* insert_sql = R"(
        INSERT INTO events (
            event_id, timestamp, received_at, source_type, source_host,
            severity, category, action, outcome,
            src_ip, dst_ip, src_port, dst_port,
            user_name, user_agent, resource, raw, metadata
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15, $16, $17, $18
        )
        ON CONFLICT (event_id) DO NOTHING;  -- Ignore duplicates
    )";

    // Step 3: Loop through buffer and execute INSERT for each event
    for (const auto& e : write_buffer_) {
        // Build parameter array
        // PostgreSQL uses $1, $2, $3... instead of ?
        const char* params[18];

        // Convert values to C strings
        std::string event_id = e.event_id;
        std::string timestamp_str = std::to_string(e.timestamp);
        std::string received_at_str = std::to_string(e.received_at);
        std::string source_type_str = to_string(e.source_type);
        std::string severity_str = to_string(e.severity);
        std::string category_str = to_string(e.category);
        std::string outcome_str = to_string(e.outcome);
        std::string src_port_str = std::to_string(e.src_port);
        std::string dst_port_str = std::to_string(e.dst_port);
        std::string metadata_str = e.metadata.dump();

        // Assign to parameter array
        params[0] = event_id.c_str();
        params[1] = timestamp_str.c_str();
        params[2] = received_at_str.c_str();
        params[3] = source_type_str.c_str();
        params[4] = e.source_host.empty() ? nullptr : e.source_host.c_str();
        params[5] = severity_str.c_str();
        params[6] = category_str.c_str();
        params[7] = e.action.empty() ? nullptr : e.action.c_str();
        params[8] = outcome_str.c_str();
        params[9] = e.src_ip.empty() ? nullptr : e.src_ip.c_str();
        params[10] = e.dst_ip.empty() ? nullptr : e.dst_ip.c_str();
        params[11] = src_port_str.c_str();
        params[12] = dst_port_str.c_str();
        params[13] = e.user.empty() ? nullptr : e.user.c_str();
        params[14] = e.user_agent.empty() ? nullptr : e.user_agent.c_str();
        params[15] = e.resource.empty() ? nullptr : e.resource.c_str();
        params[16] = e.raw.c_str();
        params[17] = metadata_str.c_str();

        // Execute INSERT
        result = PQexecParams(conn_, insert_sql, 18, nullptr, params, nullptr, nullptr, 0);

        if (PQresultStatus(result) != PGRES_COMMAND_OK) {
            LOG_WARN("Failed to insert event {}: {}",
                     e.event_id, PQerrorMessage(conn_));
        }

        PQclear(result);
    }

    // Step 4: Commit transaction (save all inserts)
    result = PQexec(conn_, "COMMIT;");
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        LOG_ERROR("Failed to commit transaction: {}",
                  PQerrorMessage(conn_));
        // Attempt rollback
        PQexec(conn_, "ROLLBACK;");
        PQclear(result);
        return;
    }
    PQclear(result);

    // Step 5: Update stats and clear buffer
    total_inserted_ += write_buffer_.size();
    LOG_DEBUG("Flushed {} events to PostgreSQL", write_buffer_.size());
    write_buffer_.clear();
}

// ═══════════════════════════════════════════════════════════════════════════
// QUERYING: FETCH EVENTS
// ═══════════════════════════════════════════════════════════════════════════

std::vector<Event> PostgresStorageEngine::query(int64_t start_ms, int64_t end_ms,
                                                const std::string& keyword,
                                                int limit, int offset) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<Event> results;

    if (!conn_) {
        LOG_ERROR("No database connection available");
        return results;
    }

    // Build SQL query based on whether we're searching keywords
    std::string sql;
    std::vector<std::string> params;
    int param_count = 0;

    if (keyword.empty()) {
        // Simple query: just by time range
        sql = "SELECT event_id, timestamp, received_at, source_type, source_host, "
              "severity, category, action, outcome, src_ip, dst_ip, src_port, dst_port, "
              "user_name, user_agent, resource, raw, metadata "
              "FROM events "
              "WHERE timestamp BETWEEN $1 AND $2 "
              "ORDER BY timestamp DESC "
              "LIMIT $3 OFFSET $4;";

        params.push_back(std::to_string(start_ms));
        params.push_back(std::to_string(end_ms));
        params.push_back(std::to_string(limit));
        params.push_back(std::to_string(offset));
        param_count = 4;
    } else {
        // Full-text search using PostgreSQL's tsvector
        sql = "SELECT event_id, timestamp, received_at, source_type, source_host, "
              "severity, category, action, outcome, src_ip, dst_ip, src_port, dst_port, "
              "user_name, user_agent, resource, raw, metadata "
              "FROM events "
              "WHERE timestamp BETWEEN $1 AND $2 "
              "AND to_tsvector('english', raw) @@ plainto_tsquery('english', $3) "
              "ORDER BY timestamp DESC "
              "LIMIT $4 OFFSET $5;";

        params.push_back(std::to_string(start_ms));
        params.push_back(std::to_string(end_ms));
        params.push_back(keyword);
        params.push_back(std::to_string(limit));
        params.push_back(std::to_string(offset));
        param_count = 5;
    }

    // Convert params to C string array
    std::vector<const char*> param_ptrs;
    for (const auto& p : params) {
        param_ptrs.push_back(p.c_str());
    }

    // Execute query
    PGresult* result = PQexecParams(conn_, sql.c_str(), param_count,
                                    nullptr, param_ptrs.data(),
                                    nullptr, nullptr, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("Query failed: {}", PQerrorMessage(conn_));
        PQclear(result);
        return results;
    }

    // Extract results
    int num_rows = PQntuples(result);
    for (int i = 0; i < num_rows; ++i) {
        results.push_back(result_to_event(result, i));
    }

    PQclear(result);
    return results;
}

std::vector<Event> PostgresStorageEngine::query_by_id(const std::string& event_id) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<Event> results;

    if (!conn_) return results;

    const char* sql = "SELECT event_id, timestamp, received_at, source_type, source_host, "
                      "severity, category, action, outcome, src_ip, dst_ip, src_port, dst_port, "
                      "user_name, user_agent, resource, raw, metadata "
                      "FROM events WHERE event_id = $1;";

    const char* params[] = { event_id.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 1, nullptr, params, nullptr, nullptr, 0);

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("Query by ID failed: {}", PQerrorMessage(conn_));
        PQclear(result);
        return results;
    }

    if (PQntuples(result) > 0) {
        results.push_back(result_to_event(result, 0));
    }

    PQclear(result);
    return results;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER: CONVERT DATABASE ROW TO EVENT
// ═══════════════════════════════════════════════════════════════════════════

Event PostgresStorageEngine::result_to_event(PGresult* result, int row) {
    Event e;

    // Helper lambda to safely get TEXT from result
    auto col_text = [&](int col) -> std::string {
        if (PQgetisnull(result, row, col)) {
            return "";
        }
        const char* value = PQgetvalue(result, row, col);
        return value ? std::string(value) : "";
    };

    // Helper lambda to safely get INTEGER
    auto col_int = [&](int col) -> int {
        if (PQgetisnull(result, row, col)) {
            return 0;
        }
        return std::stoi(col_text(col));
    };

    // Helper lambda to safely get BIGINT
    auto col_int64 = [&](int col) -> int64_t {
        if (PQgetisnull(result, row, col)) {
            return 0;
        }
        return std::stoll(col_text(col));
    };

    // Map columns to Event fields
    e.event_id    = col_text(0);
    e.timestamp   = col_int64(1);
    e.received_at = col_int64(2);
    e.source_type = source_type_from_string(col_text(3));
    e.source_host = col_text(4);
    e.severity    = severity_from_string(col_text(5));
    e.category    = category_from_string(col_text(6));
    e.action      = col_text(7);
    e.outcome     = outcome_from_string(col_text(8));
    e.src_ip      = col_text(9);
    e.dst_ip      = col_text(10);
    e.src_port    = col_int(11);
    e.dst_port    = col_int(12);
    e.user        = col_text(13);
    e.user_agent  = col_text(14);
    e.resource    = col_text(15);
    e.raw         = col_text(16);

    // Parse metadata JSON
    std::string meta = col_text(17);
    if (!meta.empty()) {
        try {
            e.metadata = nlohmann::json::parse(meta);
        } catch (...) {
            // Ignore JSON parse errors
        }
    }

    return e;
}

// ═══════════════════════════════════════════════════════════════════════════
// AGGREGATION QUERIES
// ═══════════════════════════════════════════════════════════════════════════

std::vector<std::pair<std::string, int64_t>> PostgresStorageEngine::count_by_field(
    const std::string& field) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<std::pair<std::string, int64_t>> results;

    if (!conn_) return results;

    // Whitelist allowed fields (prevent SQL injection)
    static const std::vector<std::string> allowed = {
        "source_type", "severity", "category", "action", "outcome"
    };

    bool valid = false;
    for (const auto& a : allowed) {
        if (field == a) { valid = true; break; }
    }
    if (!valid) {
        LOG_WARN("count_by_field: field '{}' not in whitelist", field);
        return results;
    }

    // Build SQL (field name is NOT a parameter, it's part of the query structure)
    std::string sql = "SELECT " + field + ", COUNT(*) as cnt FROM events "
                      "WHERE " + field + " IS NOT NULL AND " + field + " != '' "
                      "GROUP BY " + field + " ORDER BY cnt DESC;";

    PGresult* result = PQexec(conn_, sql.c_str());

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("count_by_field query failed: {}", PQerrorMessage(conn_));
        PQclear(result);
        return results;
    }

    int num_rows = PQntuples(result);
    for (int i = 0; i < num_rows; ++i) {
        std::string val = PQgetvalue(result, i, 0);
        int64_t cnt = std::stoll(PQgetvalue(result, i, 1));
        if (!val.empty()) {
            results.emplace_back(val, cnt);
        }
    }

    PQclear(result);
    return results;
}

std::vector<std::pair<std::string, int64_t>> PostgresStorageEngine::top_values(
    const std::string& field, int limit) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<std::pair<std::string, int64_t>> results;

    if (!conn_) return results;

    static const std::vector<std::string> allowed = {
        "src_ip", "dst_ip", "user_name", "action", "source_host", "user_agent"
    };

    bool valid = false;
    for (const auto& a : allowed) {
        if (field == a) { valid = true; break; }
    }
    if (!valid) {
        LOG_WARN("top_values: field '{}' not in whitelist", field);
        return results;
    }

    std::string sql = "SELECT " + field + ", COUNT(*) as cnt FROM events "
                      "WHERE " + field + " IS NOT NULL AND " + field + " != '' "
                      "GROUP BY " + field + " ORDER BY cnt DESC LIMIT " + std::to_string(limit) + ";";

    PGresult* result = PQexec(conn_, sql.c_str());

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("top_values query failed: {}", PQerrorMessage(conn_));
        PQclear(result);
        return results;
    }

    int num_rows = PQntuples(result);
    for (int i = 0; i < num_rows; ++i) {
        std::string val = PQgetvalue(result, i, 0);
        int64_t cnt = std::stoll(PQgetvalue(result, i, 1));
        if (!val.empty()) {
            results.emplace_back(val, cnt);
        }
    }

    PQclear(result);
    return results;
}

std::vector<std::pair<int64_t, int64_t>> PostgresStorageEngine::event_timeline(int hours) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<std::pair<int64_t, int64_t>> results;

    if (!conn_) return results;

    int64_t now = now_ms();
    int64_t start = now - (static_cast<int64_t>(hours) * 3600 * 1000);
    int64_t bucket_ms = 3600 * 1000;

    std::string start_str = std::to_string(start);
    std::string bucket_str = std::to_string(bucket_ms);

    std::string sql = "SELECT (timestamp / " + bucket_str + ") * " + bucket_str +
                      " as bucket, COUNT(*) as cnt "
                      "FROM events WHERE timestamp >= " + start_str + " "
                      "GROUP BY bucket ORDER BY bucket ASC;";

    PGresult* result = PQexec(conn_, sql.c_str());

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("event_timeline query failed: {}", PQerrorMessage(conn_));
        PQclear(result);
        return results;
    }

    int num_rows = PQntuples(result);
    for (int i = 0; i < num_rows; ++i) {
        int64_t bucket = std::stoll(PQgetvalue(result, i, 0));
        int64_t cnt = std::stoll(PQgetvalue(result, i, 1));
        results.emplace_back(bucket, cnt);
    }

    PQclear(result);
    return results;
}

int64_t PostgresStorageEngine::count_today() {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return 0;

    PGresult* result = PQexec(conn_, "SELECT COUNT(*) FROM events;");

    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        LOG_ERROR("count_today failed: {}", PQerrorMessage(conn_));
        PQclear(result);
        return 0;
    }

    int64_t count = std::stoll(PQgetvalue(result, 0, 0));
    PQclear(result);
    return count;
}

// ═══════════════════════════════════════════════════════════════════════════
// ALERT STORAGE
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// AUTH: USERS AND SESSIONS
// ═══════════════════════════════════════════════════════════════════════════

bool PostgresStorageEngine::create_user(const std::string& user_id,
                                         const std::string& username,
                                         const std::string& email,
                                         const std::string& password_hash,
                                         const std::string& salt,
                                         const std::string& role) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "INSERT INTO users (user_id, username, email, password_hash, salt, role, created_at) "
                      "VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (username) DO NOTHING;";
    std::string ts = std::to_string(now_ms());
    const char* params[] = { user_id.c_str(), username.c_str(), email.c_str(),
                             password_hash.c_str(), salt.c_str(),
                             role.c_str(), ts.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 7, nullptr, params, nullptr, nullptr, 0);
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) LOG_WARN("create_user failed: {}", PQerrorMessage(conn_));
    PQclear(result);
    return ok;
}

bool PostgresStorageEngine::update_user(const std::string& user_id,
                                         const std::string& email,
                                         const std::string& role) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return false;

    const char* sql = "UPDATE users SET email = $2, role = $3 WHERE user_id = $1;";
    const char* params[] = { user_id.c_str(), email.c_str(), role.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 3, nullptr, params, nullptr, nullptr, 0);
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

    // Delete user's sessions first
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

static PostgresStorageEngine::UserRecord row_to_user(PGresult* result, int row) {
    PostgresStorageEngine::UserRecord rec;
    rec.user_id       = PQgetvalue(result, row, 0);
    rec.username      = PQgetvalue(result, row, 1);
    rec.email         = PQgetvalue(result, row, 2);
    rec.password_hash = PQgetvalue(result, row, 3);
    rec.salt          = PQgetvalue(result, row, 4);
    rec.role          = PQgetvalue(result, row, 5);
    rec.created_at    = std::stoll(PQgetvalue(result, row, 6));
    return rec;
}

std::optional<PostgresStorageEngine::UserRecord>
PostgresStorageEngine::get_user_by_username(const std::string& username) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    if (!conn_) return std::nullopt;

    const char* sql = "SELECT user_id, username, email, password_hash, salt, role, created_at FROM users WHERE username = $1;";
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

    const char* sql = "SELECT user_id, username, email, password_hash, salt, role, created_at FROM users WHERE email = $1;";
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

    PGresult* result = PQexec(conn_, "SELECT user_id, username, email, password_hash, salt, role, created_at FROM users ORDER BY created_at;");
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

// ═══════════════════════════════════════════════════════════════════════════
// CUSTOM RULES STORAGE
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// GEO QUERIES
// ═══════════════════════════════════════════════════════════════════════════

std::vector<PostgresStorageEngine::GeoPoint> PostgresStorageEngine::get_geo_points(
    const std::string& source_filter) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<GeoPoint> results;
    if (!conn_) return results;

    // Query events that have latitude/longitude in their JSONB metadata
    // Aggregate by location + source to avoid duplicate pins
    std::string sql =
        "SELECT metadata->>'latitude' AS lat, "
        "       metadata->>'longitude' AS lng, "
        "       COALESCE(metadata->>'city', metadata->>'location', src_ip) AS label, "
        "       source_type, "
        "       COALESCE(metadata->>'geo_type', 'event') AS point_type, "
        "       COALESCE(metadata->>'status', 'online') AS status, "
        "       COUNT(*) AS cnt "
        "FROM events "
        "WHERE metadata ? 'latitude' AND metadata ? 'longitude' ";

    std::vector<const char*> params;
    std::string source_val;
    if (!source_filter.empty() && source_filter != "all") {
        source_val = source_filter;
        sql += "AND source_type = $1 ";
        params.push_back(source_val.c_str());
    }

    sql += "GROUP BY lat, lng, label, source_type, point_type, status "
           "ORDER BY cnt DESC LIMIT 500;";

    PGresult* res = PQexecParams(conn_, sql.c_str(),
                                 static_cast<int>(params.size()),
                                 nullptr, params.empty() ? nullptr : params.data(),
                                 nullptr, nullptr, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        LOG_ERROR("get_geo_points query failed: {}", PQerrorMessage(conn_));
        PQclear(res);
        return results;
    }

    int rows = PQntuples(res);
    for (int i = 0; i < rows; ++i) {
        GeoPoint pt;
        try {
            pt.latitude  = std::stod(PQgetvalue(res, i, 0));
            pt.longitude = std::stod(PQgetvalue(res, i, 1));
        } catch (...) { continue; }
        pt.label      = PQgetvalue(res, i, 2);
        pt.source     = PQgetvalue(res, i, 3);
        pt.point_type = PQgetvalue(res, i, 4);
        pt.status     = PQgetvalue(res, i, 5);
        pt.count      = std::stoll(PQgetvalue(res, i, 6));
        results.push_back(std::move(pt));
    }

    PQclear(res);
    return results;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTOR STORAGE
// ═══════════════════════════════════════════════════════════════════════════

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

int64_t PostgresStorageEngine::alert_count() const {
    if (!conn_) return 0;

    // Need to cast away const because PQexec isn't const-correct in libpq
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
