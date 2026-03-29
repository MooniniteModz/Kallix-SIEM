#include "parser/parser_registry.h"
#include "parser/fortigate_parser.h"
#include "parser/windows_parser.h"
#include "parser/m365_parser.h"
#include "parser/azure_parser.h"
#include "parser/unifi_parser.h"
#include "parser/syslog_parser.h"
#include "common/logger.h"

#include <algorithm>

namespace outpost {

void ParserRegistry::register_defaults() {
    // Order matters: specific format parsers first, generic catch-all last.
    //
    // Why this order:
    //   1. FortiGate: key=value format, fast rejection via "logid=" check
    //   2. Windows:   XML/JSON with EventID, fast rejection via format check
    //   3. M365:      JSON with "Workload" field, only matches M365 API data
    //   4. Azure:     JSON with "operationName" field, only matches Azure data
    //   5. UniFi:     JSON with UniFi-specific fields (mac, site_id, etc.)
    //   6. Syslog:    RFC 3164/5424 catch-all — must be LAST
    //
    // Each parser quickly rejects messages it can't handle (returns nullopt),
    // so the overhead of trying all parsers is minimal.

    register_parser("fortigate", [] { return std::make_unique<FortiGateParser>(); });
    register_parser("windows",   [] { return std::make_unique<WindowsParser>(); });
    register_parser("m365",      [] { return std::make_unique<M365Parser>(); });
    register_parser("azure",     [] { return std::make_unique<AzureParser>(); });
    register_parser("unifi",     [] { return std::make_unique<UniFiParser>(); });
    register_parser("syslog",    [] { return std::make_unique<SyslogParser>(); });

    LOG_INFO("Parser registry: {} parsers registered", parsers_.size());
    for (const auto& p : parsers_) {
        LOG_INFO("  - {}", p->name());
    }
}

void ParserRegistry::register_parser(const std::string& name, ParserFactory factory) {
    // Check if a parser with this name already exists
    for (size_t i = 0; i < registry_.size(); ++i) {
        if (registry_[i].name == name) {
            // Replace existing
            registry_[i].factory = factory;
            parsers_[i] = factory();
            LOG_INFO("Parser registry: replaced '{}'", name);
            return;
        }
    }

    // Add new
    registry_.push_back({name, factory});
    parsers_.push_back(factory());
}

bool ParserRegistry::remove_parser(const std::string& name) {
    for (size_t i = 0; i < registry_.size(); ++i) {
        if (registry_[i].name == name) {
            registry_.erase(registry_.begin() + static_cast<long>(i));
            parsers_.erase(parsers_.begin() + static_cast<long>(i));
            LOG_INFO("Parser registry: removed '{}'", name);
            return true;
        }
    }
    return false;
}

std::vector<std::string> ParserRegistry::parser_names() const {
    std::vector<std::string> names;
    names.reserve(registry_.size());
    for (const auto& entry : registry_) {
        names.push_back(entry.name);
    }
    return names;
}

} // namespace outpost
