#pragma once

#include "parser/parser.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace outpost {

/// Factory function type for creating parser instances
using ParserFactory = std::function<std::unique_ptr<Parser>()>;

/// ────────────────────────────────────────────────────────────────
/// ParserRegistry: manages parser lifecycle and dispatch order
///
/// Why this exists:
///   Previously, parsers were hardcoded in main.cpp with implicit
///   ordering. The registry makes the order explicit, configurable,
///   and documents why it matters (specific parsers before catch-all).
///
/// Usage:
///   ParserRegistry registry;
///   registry.register_defaults();   // adds all built-in parsers
///   auto& parsers = registry.parsers();
/// ────────────────────────────────────────────────────────────────
class ParserRegistry {
public:
    /// Register all built-in parsers in the correct default order.
    /// Order: specific format parsers first, catch-all (syslog) last.
    void register_defaults();

    /// Register a parser by name and factory function.
    /// If a parser with the same name exists, it is replaced.
    void register_parser(const std::string& name, ParserFactory factory);

    /// Remove a parser by name. Returns true if found and removed.
    bool remove_parser(const std::string& name);

    /// Get the ordered list of parsers (for iteration in parser_worker)
    std::vector<std::unique_ptr<Parser>>& parsers() { return parsers_; }
    const std::vector<std::unique_ptr<Parser>>& parsers() const { return parsers_; }

    /// Get the name of each registered parser, in order
    std::vector<std::string> parser_names() const;

    /// Number of registered parsers
    size_t size() const { return parsers_.size(); }

private:
    struct Entry {
        std::string name;
        ParserFactory factory;
    };

    std::vector<std::unique_ptr<Parser>> parsers_;
    std::vector<Entry> registry_;  // keeps factory info for potential re-ordering
};

} // namespace outpost
