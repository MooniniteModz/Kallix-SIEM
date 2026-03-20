#include "rules/rule_engine.h"
#include "common/utils.h"
#include "common/logger.h"

#include <algorithm>

namespace outpost {

// Helper to get a field value from an event by name
static std::string get_field(const Event& e, const std::string& field) {
    if (field == "src_ip")      return e.src_ip;
    if (field == "dst_ip")      return e.dst_ip;
    if (field == "user")        return e.user;
    if (field == "source_host") return e.source_host;
    if (field == "action")      return e.action;
    if (field == "user_agent")  return e.user_agent;
    if (field == "resource")    return e.resource;
    if (field == "source_type") return to_string(e.source_type);
    if (e.metadata.contains(field)) {
        auto& val = e.metadata[field];
        if (val.is_string()) return val.get<std::string>();
        return val.dump();
    }
    return "";
}

RuleEngine::RuleEngine(PostgresStorageEngine& storage) : storage_(storage) {}

void RuleEngine::load_rules(const std::string& rules_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_ = load_rules_from_directory(rules_dir);

    int enabled = 0;
    for (const auto& r : rules_) {
        if (r.enabled) ++enabled;
    }
    LOG_INFO("Rule engine loaded {} rules ({} enabled)", rules_.size(), enabled);
}

void RuleEngine::reload_rules(const std::string& rules_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_ = load_rules_from_directory(rules_dir);

    // Clear state for rules that no longer exist
    // (keep state for rules that still exist to maintain window continuity)
    std::unordered_set<std::string> active_ids;
    for (const auto& r : rules_) active_ids.insert(r.id);

    for (auto it = threshold_windows_.begin(); it != threshold_windows_.end(); ) {
        if (active_ids.count(it->first) == 0) it = threshold_windows_.erase(it);
        else ++it;
    }
    for (auto it = sequence_states_.begin(); it != sequence_states_.end(); ) {
        if (active_ids.count(it->first) == 0) it = sequence_states_.erase(it);
        else ++it;
    }

    LOG_INFO("Rule engine reloaded: {} rules", rules_.size());
}

void RuleEngine::evaluate(const Event& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Periodic cleanup of expired windows (every 30 seconds)
    int64_t now = now_ms();
    if (now - last_cleanup_ > 30000) {
        cleanup_windows(now);
        last_cleanup_ = now;
    }

    for (const auto& rule : rules_) {
        if (!rule.enabled) continue;
        if (!rule.filter.matches(event)) continue;

        switch (rule.type) {
            case RuleType::Threshold:
                evaluate_threshold(rule, event);
                break;
            case RuleType::Sequence:
                evaluate_sequence(rule, event);
                break;
            case RuleType::ValueList:
                evaluate_valuelist(rule, event);
                break;
            default:
                break;
        }
    }
}

void RuleEngine::evaluate_threshold(const Rule& rule, const Event& event) {
    const auto& cfg = rule.threshold_config;

    // Determine group key
    std::string group_key = cfg.group_by.empty() ? "_global_" : get_field(event, cfg.group_by);
    if (group_key.empty()) group_key = "_empty_";

    // Add to sliding window
    auto& window = threshold_windows_[rule.id][group_key];
    window.push_back({event.timestamp, event.event_id});

    // Expire old entries
    int64_t cutoff = event.timestamp - (static_cast<int64_t>(cfg.window_seconds) * 1000);
    while (!window.empty() && window.front().timestamp < cutoff) {
        window.pop_front();
    }

    // Check threshold
    if (static_cast<int>(window.size()) >= cfg.threshold) {
        // Collect event IDs for the alert
        std::vector<std::string> event_ids;
        for (const auto& entry : window) {
            event_ids.push_back(entry.event_id);
        }

        fire_alert(rule, group_key, event_ids);

        // Clear the window to prevent continuous firing
        // (cooldown also applies, but clearing gives a clean slate)
        window.clear();
    }
}

void RuleEngine::evaluate_sequence(const Rule& rule, const Event& event) {
    const auto& cfg = rule.sequence_config;
    if (cfg.steps.empty()) return;

    std::string group_key = cfg.group_by.empty() ? "_global_" : get_field(event, cfg.group_by);
    if (group_key.empty()) group_key = "_empty_";

    auto& state = sequence_states_[rule.id][group_key];

    // Check if event matches the current expected step
    if (state.current_step < cfg.steps.size()) {
        const auto& expected_step = cfg.steps[state.current_step];

        if (expected_step.filter.matches(event)) {
            // First step: record start time
            if (state.current_step == 0) {
                state.first_event_time = event.timestamp;
            }

            // Check if we're still within the time window
            int64_t elapsed_ms = event.timestamp - state.first_event_time;
            if (elapsed_ms <= static_cast<int64_t>(cfg.window_seconds) * 1000) {
                state.event_ids.push_back(event.event_id);
                state.current_step++;

                // Sequence complete?
                if (state.current_step >= cfg.steps.size()) {
                    fire_alert(rule, group_key, state.event_ids);
                    // Reset
                    state = SequenceState{};
                }
            } else {
                // Window expired, reset sequence
                state = SequenceState{};
                // Re-check if this event could be step 0 of a new sequence
                if (cfg.steps[0].filter.matches(event)) {
                    state.first_event_time = event.timestamp;
                    state.event_ids.push_back(event.event_id);
                    state.current_step = 1;
                }
            }
        }
    }
}

void RuleEngine::evaluate_valuelist(const Rule& rule, const Event& event) {
    const auto& cfg = rule.valuelist_config;
    if (cfg.field.empty() || cfg.values.empty()) return;

    std::string val = get_field(event, cfg.field);
    if (cfg.values.count(val)) {
        fire_alert(rule, val, {event.event_id});
    }
}

void RuleEngine::fire_alert(const Rule& rule, const std::string& group_key,
                             const std::vector<std::string>& event_ids) {
    // Check cooldown
    std::string cooldown_key = rule.id + "|" + group_key;
    int64_t now = now_ms();

    auto it = alert_cooldown_.find(cooldown_key);
    if (it != alert_cooldown_.end() && (now - it->second) < COOLDOWN_MS) {
        return;  // Still in cooldown
    }
    alert_cooldown_[cooldown_key] = now;

    // Build alert
    Alert alert;
    alert.alert_id    = generate_uuid();
    alert.rule_id     = rule.id;
    alert.rule_name   = rule.name;
    alert.severity    = rule.severity;
    alert.group_key   = group_key;
    alert.event_ids   = event_ids;
    alert.created_at  = now;
    alert.acknowledged = false;

    // Build description
    alert.description = rule.description;
    if (!group_key.empty() && group_key != "_global_" && group_key != "_empty_") {
        alert.description += " [" + group_key + "]";
    }
    if (!event_ids.empty()) {
        alert.description += " (" + std::to_string(event_ids.size()) + " events)";
    }

    // Write to storage
    storage_.insert_alert(alert);

    alerts_fired_++;

    LOG_WARN("ALERT | {} | {} | {} | {} events | group: {}",
             to_string(rule.severity), rule.id, rule.name,
             event_ids.size(), group_key);

    // Notify callbacks
    for (const auto& cb : alert_callbacks_) {
        try { cb(alert); } catch (...) {}
    }
}

void RuleEngine::cleanup_windows(int64_t now) {
    // Clean threshold windows
    for (auto& [rule_id, groups] : threshold_windows_) {
        for (auto it = groups.begin(); it != groups.end(); ) {
            auto& window = it->second;
            // Find the rule to get window size
            int window_ms = 600000;  // default 10 min
            for (const auto& r : rules_) {
                if (r.id == rule_id) {
                    window_ms = r.threshold_config.window_seconds * 1000;
                    break;
                }
            }
            int64_t cutoff = now - window_ms;
            while (!window.empty() && window.front().timestamp < cutoff) {
                window.pop_front();
            }
            if (window.empty()) {
                it = groups.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clean stale sequence states (older than 2x the window)
    for (auto& [rule_id, groups] : sequence_states_) {
        for (auto it = groups.begin(); it != groups.end(); ) {
            if (it->second.first_event_time > 0 &&
                (now - it->second.first_event_time) > 1200000) {  // 20 min max
                it = groups.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clean expired cooldowns
    for (auto it = alert_cooldown_.begin(); it != alert_cooldown_.end(); ) {
        if ((now - it->second) > COOLDOWN_MS * 2) {
            it = alert_cooldown_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<Alert> RuleEngine::get_alerts(int limit) {
    return storage_.get_alerts(limit);
}

int64_t RuleEngine::alert_count() const {
    return storage_.alert_count();
}

size_t RuleEngine::rule_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

} // namespace outpost
