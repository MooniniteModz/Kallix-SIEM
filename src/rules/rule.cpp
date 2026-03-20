#include "rules/rule.h"
#include "common/logger.h"

#include <yaml-cpp/yaml.h>
#include <filesystem>
#include <fstream>
#include <algorithm>

namespace outpost {

std::string to_string(RuleSeverity s) {
    switch (s) {
        case RuleSeverity::Low:      return "low";
        case RuleSeverity::Medium:   return "medium";
        case RuleSeverity::High:     return "high";
        case RuleSeverity::Critical: return "critical";
        default: return "medium";
    }
}

RuleSeverity rule_severity_from_string(const std::string& s) {
    if (s == "low")      return RuleSeverity::Low;
    if (s == "medium")   return RuleSeverity::Medium;
    if (s == "high")     return RuleSeverity::High;
    if (s == "critical") return RuleSeverity::Critical;
    return RuleSeverity::Medium;
}

// ── Field accessor helper ──
static std::string get_event_field(const Event& e, const std::string& field) {
    if (field == "source_type") return to_string(e.source_type);
    if (field == "category")    return to_string(e.category);
    if (field == "action")      return e.action;
    if (field == "severity")    return to_string(e.severity);
    if (field == "outcome")     return to_string(e.outcome);
    if (field == "src_ip")      return e.src_ip;
    if (field == "dst_ip")      return e.dst_ip;
    if (field == "user")        return e.user;
    if (field == "source_host") return e.source_host;
    if (field == "user_agent")  return e.user_agent;
    if (field == "resource")    return e.resource;
    // Check metadata
    if (e.metadata.contains(field)) {
        auto& val = e.metadata[field];
        if (val.is_string()) return val.get<std::string>();
        return val.dump();
    }
    return "";
}

bool RuleFilter::matches(const Event& event) const {
    if (!source_type.empty() && to_string(event.source_type) != source_type)
        return false;
    if (!category.empty() && to_string(event.category) != category)
        return false;
    if (!action.empty() && event.action != action)
        return false;
    if (!field_match.empty() && !field_value.empty()) {
        std::string val = get_event_field(event, field_match);
        if (val != field_value) return false;
    }
    return true;
}

// ── YAML Loading ──

static RuleFilter parse_filter(const YAML::Node& node) {
    RuleFilter f;
    if (!node || !node.IsMap()) return f;
    if (node["source_type"]) f.source_type = node["source_type"].as<std::string>();
    if (node["category"])    f.category = node["category"].as<std::string>();
    if (node["action"])      f.action = node["action"].as<std::string>();
    if (node["field"])       f.field_match = node["field"].as<std::string>();
    if (node["value"])       f.field_value = node["value"].as<std::string>();
    return f;
}

static Rule parse_rule(const YAML::Node& node) {
    Rule rule;

    rule.id          = node["id"].as<std::string>("");
    rule.name        = node["name"].as<std::string>("");
    rule.description = node["description"].as<std::string>("");
    rule.severity    = rule_severity_from_string(node["severity"].as<std::string>("medium"));
    rule.enabled     = node["enabled"].as<bool>(true);

    // Tags
    if (node["tags"] && node["tags"].IsSequence()) {
        for (const auto& t : node["tags"]) {
            rule.tags.push_back(t.as<std::string>());
        }
    }

    // Filter
    if (node["filter"]) {
        rule.filter = parse_filter(node["filter"]);
    }

    // Type and type-specific config
    std::string type_str = node["type"].as<std::string>("threshold");
    if (type_str == "threshold") {
        rule.type = RuleType::Threshold;
        if (node["condition"]) {
            auto& c = node["condition"];
            rule.threshold_config.threshold      = c["threshold"].as<int>(5);
            rule.threshold_config.window_seconds  = c["window_seconds"].as<int>(300);
            rule.threshold_config.group_by        = c["group_by"].as<std::string>("");

            // Support "5m", "1h" style windows
            if (c["window"]) {
                std::string w = c["window"].as<std::string>();
                int val = 0;
                try { val = std::stoi(w); } catch (...) {}
                if (w.back() == 'm') rule.threshold_config.window_seconds = val * 60;
                else if (w.back() == 'h') rule.threshold_config.window_seconds = val * 3600;
                else if (w.back() == 's') rule.threshold_config.window_seconds = val;
                else rule.threshold_config.window_seconds = val;
            }
        }
    } else if (type_str == "sequence") {
        rule.type = RuleType::Sequence;
        if (node["condition"]) {
            auto& c = node["condition"];
            rule.sequence_config.window_seconds = c["window_seconds"].as<int>(300);
            rule.sequence_config.group_by       = c["group_by"].as<std::string>("");

            if (c["window"]) {
                std::string w = c["window"].as<std::string>();
                int val = 0;
                try { val = std::stoi(w); } catch (...) {}
                if (w.back() == 'm') rule.sequence_config.window_seconds = val * 60;
                else if (w.back() == 'h') rule.sequence_config.window_seconds = val * 3600;
                else rule.sequence_config.window_seconds = val;
            }

            if (c["steps"] && c["steps"].IsSequence()) {
                for (const auto& s : c["steps"]) {
                    SequenceStep step;
                    step.label = s["label"].as<std::string>("");
                    step.filter = parse_filter(s["filter"]);
                    rule.sequence_config.steps.push_back(step);
                }
            }
        }
    } else if (type_str == "valuelist") {
        rule.type = RuleType::ValueList;
        if (node["condition"]) {
            auto& c = node["condition"];
            rule.valuelist_config.field = c["field"].as<std::string>("");
            if (c["values"] && c["values"].IsSequence()) {
                for (const auto& v : c["values"]) {
                    rule.valuelist_config.values.insert(v.as<std::string>());
                }
            }
        }
    }

    return rule;
}

std::vector<Rule> load_rules_from_file(const std::string& path) {
    std::vector<Rule> rules;
    try {
        YAML::Node doc = YAML::LoadFile(path);
        if (doc["rules"] && doc["rules"].IsSequence()) {
            for (const auto& node : doc["rules"]) {
                auto rule = parse_rule(node);
                if (!rule.id.empty()) {
                    rules.push_back(std::move(rule));
                }
            }
        } else if (doc.IsMap() && doc["id"]) {
            // Single rule document
            auto rule = parse_rule(doc);
            if (!rule.id.empty()) rules.push_back(std::move(rule));
        }
        LOG_INFO("Loaded {} rules from {}", rules.size(), path);
    } catch (const std::exception& ex) {
        LOG_ERROR("Failed to load rules from {}: {}", path, ex.what());
    }
    return rules;
}

std::vector<Rule> load_rules_from_directory(const std::string& dir) {
    std::vector<Rule> all_rules;
    namespace fs = std::filesystem;

    if (!fs::exists(dir)) {
        LOG_WARN("Rules directory does not exist: {}", dir);
        return all_rules;
    }

    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            if (ext == ".yaml" || ext == ".yml") {
                auto rules = load_rules_from_file(entry.path().string());
                all_rules.insert(all_rules.end(), rules.begin(), rules.end());
            }
        }
    }

    LOG_INFO("Total rules loaded: {}", all_rules.size());
    return all_rules;
}

} // namespace outpost
