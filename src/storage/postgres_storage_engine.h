#pragma once

#include "common/event.h"
#include <libpq-fe.h>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace outpost {

// Forward declaration
struct Alert;

struct PostgresConfig {
    std::string host           = "localhost";
    int         port           = 5432;
    std::string dbname         = "outpost";
    std::string user           = "postgres";
    std::string password       = "";
    int         batch_size     = 1000;     // events per transaction
    int         flush_interval_ms = 1000;  // max time between flushes
};

/// ────────────────────────────────────────────────────────────────
/// PostgresStorageEngine: PostgreSQL-based event storage
///
/// Architecture:
///   1. init() connects to PostgreSQL and creates schema
///   2. insert() buffers events in memory
///   3. flush() executes prepared statements in a transaction
///   4. query() uses parameterized queries to prevent SQL injection
///   5. Full-text search with PostgreSQL tsvector
/// ────────────────────────────────────────────────────────────────
class PostgresStorageEngine {
public:
    /// Constructor: takes configuration
    explicit PostgresStorageEngine(const PostgresConfig& config = {});

    /// Destructor: flushes buffer and closes connection
    ~PostgresStorageEngine();

    /// Initialize: connect to PostgreSQL and create tables
    bool init();

    /// Insert a single event (buffered; call flush() to commit)
    void insert(const Event& event);

    /// Flush the write buffer to database
    void flush();

    /// Query events by time range and optional keyword
    std::vector<Event> query(int64_t start_ms, int64_t end_ms,
                             const std::string& keyword = "",
                             int limit = 100, int offset = 0);

    /// Query a single event by ID
    std::vector<Event> query_by_id(const std::string& event_id);

    /// Count events grouped by a field
    std::vector<std::pair<std::string, int64_t>> count_by_field(const std::string& field);

    /// Top N values for a field
    std::vector<std::pair<std::string, int64_t>> top_values(const std::string& field, int limit = 10);

    /// Event count per hour for the last N hours
    std::vector<std::pair<int64_t, int64_t>> event_timeline(int hours = 24);

    /// Get total event count
    int64_t count_today();

    /// Get total events inserted in this session
    uint64_t total_inserted() const { return total_inserted_; }

    // ── Alert methods ──
    void insert_alert(const Alert& alert);
    std::vector<Alert> get_alerts(int limit = 100);
    int64_t alert_count() const;
    bool update_alert_status(const std::string& alert_id, const std::string& status);

    // ── Auth methods ──
    bool create_user(const std::string& user_id, const std::string& username,
                     const std::string& email,
                     const std::string& password_hash, const std::string& salt,
                     const std::string& role);
    bool update_user(const std::string& user_id, const std::string& email, const std::string& role);
    bool update_user_password(const std::string& user_id,
                              const std::string& password_hash, const std::string& salt);
    bool delete_user(const std::string& user_id);

    struct UserRecord { std::string user_id, username, email, password_hash, salt, role; int64_t created_at = 0; };
    std::optional<UserRecord> get_user_by_username(const std::string& username);
    std::optional<UserRecord> get_user_by_email(const std::string& email);
    std::vector<UserRecord> list_users();
    int user_count();

    bool create_session(const std::string& token, const std::string& user_id,
                        int64_t created_at, int64_t expires_at);
    struct SessionInfo { std::string user_id, username, email, role; };
    std::optional<SessionInfo> validate_session(const std::string& token);
    bool delete_session(const std::string& token);

    // ── Custom rules methods ──
    struct CustomRuleRecord {
        std::string id, name, description, severity, type;
        std::string source_type, category, action, field_match, field_value;
        std::string config_json;   // threshold/sequence/valuelist config as JSON
        std::string tags_json;     // tags as JSON array
        bool enabled = true;
        int64_t created_at = 0, updated_at = 0;
    };
    std::vector<CustomRuleRecord> get_custom_rules();
    bool save_custom_rule(const CustomRuleRecord& r);
    bool update_custom_rule(const CustomRuleRecord& r);
    bool delete_custom_rule(const std::string& id);

    // ── Geo query methods ──
    struct GeoPoint {
        double latitude = 0.0, longitude = 0.0;
        std::string label;          // city, hostname, or IP
        std::string source;         // "Azure", "UniFi", "FortiGate", etc.
        std::string point_type;     // "login", "device", "event"
        std::string status;         // "online", "offline", "alert"
        std::string details;        // JSON string with extra info
        int64_t count = 1;
    };
    std::vector<GeoPoint> get_geo_points(const std::string& source_filter = "");

    // ── Connector methods ──
    struct ConnectorRecord {
        std::string id, name, type, status;
        bool enabled = false;
        std::string settings_json;
        int64_t event_count = 0, created_at = 0, updated_at = 0;
    };
    std::vector<ConnectorRecord> get_connectors();
    std::optional<ConnectorRecord> get_connector(const std::string& id);
    bool save_connector(const ConnectorRecord& c);
    bool update_connector(const ConnectorRecord& c);
    bool delete_connector(const std::string& id);

private:
    /// Helper: Convert a PGresult row to an Event struct
    Event result_to_event(PGresult* result, int row);

    /// Helper: Check if a query succeeded
    bool check_result(PGresult* result, const std::string& operation);

    /// Helper: Execute a query and return results
    PGresult* execute_query(const std::string& sql,
                            const std::vector<std::string>& params);

    /// Configuration
    PostgresConfig config_;

    /// PostgreSQL connection object (nullptr if not connected)
    PGconn* conn_ = nullptr;

    /// Write buffer
    std::vector<Event> write_buffer_;

    /// Thread safety for buffer
    std::mutex write_mutex_;

    /// Thread safety for connection (libpq is not thread-safe per-connection)
    std::mutex conn_mutex_;

    /// Stats
    uint64_t total_inserted_ = 0;
};

} // namespace outpost
