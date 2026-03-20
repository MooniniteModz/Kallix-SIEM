#pragma once

#include "common/event.h"
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace outpost {

/// ── Rule severity levels ──
enum class RuleSeverity : uint8_t {
    Low, Medium, High, Critical
};

std::string to_string(RuleSeverity s);
RuleSeverity rule_severity_from_string(const std::string& s);

/// ── Rule types ──
enum class RuleType : uint8_t {
    Threshold,    // N events matching filter within time window
    Sequence,     // ordered events within window
    ValueList,    // event field matches a known-bad list
    Anomaly       // deviation from baseline (future)
};

/// ── Filter condition: which events does this rule apply to? ──
struct RuleFilter {
    std::string source_type;   // empty = any
    std::string category;      // empty = any
    std::string action;        // empty = any
    std::string severity_min;  // empty = any; "warning" means warning+
    std::string field_match;   // metadata field to check
    std::string field_value;   // value to match (supports simple wildcards)

    /// Does this event match the filter?
    bool matches(const Event& event) const;
};

/// ── Threshold rule config ──
struct ThresholdConfig {
    int         threshold = 5;
    int         window_seconds = 300;  // 5 minutes
    std::string group_by;              // field to group by (src_ip, user, etc.)
};

/// ── Sequence rule config ──
struct SequenceStep {
    RuleFilter  filter;
    std::string label;  // human-readable step name
};

struct SequenceConfig {
    std::vector<SequenceStep> steps;
    int         window_seconds = 300;
    std::string group_by;
};

/// ── Value list config ──
struct ValueListConfig {
    std::string field;  // which event field to check
    std::unordered_set<std::string> values;  // known-bad values
};

/// ── Complete rule definition ──
struct Rule {
    std::string   id;
    std::string   name;
    std::string   description;
    RuleSeverity  severity = RuleSeverity::Medium;
    RuleType      type = RuleType::Threshold;
    RuleFilter    filter;
    std::vector<std::string> tags;

    // Type-specific configs (only one is active based on type)
    ThresholdConfig threshold_config;
    SequenceConfig  sequence_config;
    ValueListConfig valuelist_config;

    bool enabled = true;
};

/// ── Alert: generated when a rule fires ──
struct Alert {
    std::string   alert_id;
    std::string   rule_id;
    std::string   rule_name;
    RuleSeverity  severity;
    std::string   description;
    std::vector<std::string> event_ids;
    std::string   group_key;       // what triggered it (e.g., the IP or user)
    int64_t       created_at;
    bool          acknowledged = false;
};

/// Load rules from a YAML file
std::vector<Rule> load_rules_from_file(const std::string& path);

/// Load all rules from a directory of YAML files
std::vector<Rule> load_rules_from_directory(const std::string& dir);

} // namespace outpost
