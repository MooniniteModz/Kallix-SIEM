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
    conn_str << " sslmode=" << config_.sslmode;

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

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            expires_at BIGINT NOT NULL
        );

        ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret             TEXT    DEFAULT '';
        ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled             BOOLEAN DEFAULT FALSE;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes            TEXT    DEFAULT '[]';
        ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change   BOOLEAN DEFAULT FALSE;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name              TEXT    DEFAULT '';
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name               TEXT    DEFAULT '';

        CREATE TABLE IF NOT EXISTS pending_mfa (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            expires_at BIGINT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pending_password_change (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            expires_at BIGINT NOT NULL
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
        } catch (const std::exception& ex) {
            LOG_DEBUG("Event metadata JSON parse failed: {}", ex.what());
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

    // Field name is whitelisted above — safe to interpolate into query structure
    std::string sql = "SELECT " + field + ", COUNT(*) as cnt FROM events "
                      "WHERE " + field + " IS NOT NULL AND " + field + " != '' "
                      "GROUP BY " + field + " ORDER BY cnt DESC;";

    PGresult* result = PQexecParams(conn_, sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);

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

    std::string limit_str = std::to_string(limit);
    std::string sql = "SELECT " + field + ", COUNT(*) as cnt FROM events "
                      "WHERE " + field + " IS NOT NULL AND " + field + " != '' "
                      "GROUP BY " + field + " ORDER BY cnt DESC LIMIT $1;";
    const char* params[1] = { limit_str.c_str() };
    PGresult* result = PQexecParams(conn_, sql.c_str(), 1, nullptr, params, nullptr, nullptr, 0);

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

    const char* sql = "SELECT (timestamp / $1) * $1 as bucket, COUNT(*) as cnt "
                      "FROM events WHERE timestamp >= $2 "
                      "GROUP BY bucket ORDER BY bucket ASC;";
    const char* params[2] = { bucket_str.c_str(), start_str.c_str() };
    PGresult* result = PQexecParams(conn_, sql, 2, nullptr, params, nullptr, nullptr, 0);

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

// Domain-specific methods are split into separate files:
//   postgres_alerts.cpp     — Alert CRUD
//   postgres_auth.cpp       — User and session management
//   postgres_rules.cpp      — Custom rules CRUD
//   postgres_connectors.cpp — Connector CRUD
//   postgres_geo.cpp        — Geospatial queries

} // namespace outpost
