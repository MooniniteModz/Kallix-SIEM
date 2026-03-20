#pragma once

#include "rules/rule.h"
#include "storage/postgres_storage_engine.h"

#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace outpost {

/// ── Sliding window entry for threshold tracking ──
struct WindowEntry {
    int64_t     timestamp;
    std::string event_id;
};

/// ── Sequence tracking state per group key ──
struct SequenceState {
    size_t  current_step = 0;    // which step we're expecting next
    int64_t first_event_time = 0;
    std::vector<std::string> event_ids;
};

/// ────────────────────────────────────────────────────────────────
/// RuleEngine: evaluates detection rules against a stream of events.
///
/// Maintains sliding windows for threshold rules, sequence state
/// for ordered pattern detection, and fires alerts when conditions
/// are met. Alerts are written to the storage engine.
///
/// Thread safety: evaluate() is called from parser worker threads.
/// Internal state is mutex-protected.
/// ────────────────────────────────────────────────────────────────
class RuleEngine {
public:
    explicit RuleEngine(PostgresStorageEngine& storage);

    /// Load rules from a directory
    void load_rules(const std::string& rules_dir);

    /// Reload rules (e.g., on SIGHUP)
    void reload_rules(const std::string& rules_dir);

    /// Evaluate a single event against all active rules.
    /// Called from parser workers for each parsed event.
    void evaluate(const Event& event);

    /// Get all alerts (from storage)
    std::vector<Alert> get_alerts(int limit = 100);

    /// Get alert count
    int64_t alert_count() const;

    /// Get loaded rule count
    size_t rule_count() const;

    /// Get alerts generated since last call (for stats)
    uint64_t alerts_fired() const { return alerts_fired_; }

    /// Register a callback for new alerts (e.g., for future webhook/email)
    using AlertCallback = std::function<void(const Alert&)>;
    void on_alert(AlertCallback cb) { alert_callbacks_.push_back(std::move(cb)); }

private:
    void evaluate_threshold(const Rule& rule, const Event& event);
    void evaluate_sequence(const Rule& rule, const Event& event);
    void evaluate_valuelist(const Rule& rule, const Event& event);

    void fire_alert(const Rule& rule, const std::string& group_key,
                    const std::vector<std::string>& event_ids);

    /// Clean expired entries from sliding windows
    void cleanup_windows(int64_t now_ms);

    PostgresStorageEngine& storage_;
    std::vector<Rule> rules_;
    mutable std::mutex mutex_;

    // Threshold state: rule_id -> group_key -> sliding window
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::deque<WindowEntry>>> threshold_windows_;

    // Sequence state: rule_id -> group_key -> sequence progress
    std::unordered_map<std::string,
        std::unordered_map<std::string, SequenceState>> sequence_states_;

    // Dedup: prevent the same rule+group from firing repeatedly
    // rule_id+group_key -> last alert time
    std::unordered_map<std::string, int64_t> alert_cooldown_;
    static constexpr int64_t COOLDOWN_MS = 300000;  // 5 minute cooldown

    uint64_t alerts_fired_ = 0;
    int64_t last_cleanup_ = 0;

    std::vector<AlertCallback> alert_callbacks_;
};

} // namespace outpost
