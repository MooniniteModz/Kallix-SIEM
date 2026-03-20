#pragma once

#include "common/event.h"
#include <libpq-fe.h>  // PostgreSQL C client library
#include <memory>
#include <mutex>
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

    /// Stats
    uint64_t total_inserted_ = 0;
};

} // namespace outpost
