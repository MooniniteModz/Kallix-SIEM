#pragma once

#include "parser/parser.h"

namespace outpost {

/// Parser for UniFi Site Manager API responses (api.ui.com).
/// Recognizes device/host JSON objects and normalizes them into Events.
class UniFiParser : public Parser {
public:
    std::optional<Event> parse(const RawMessage& raw) override;
    const char* name() const override { return "UniFi"; }
};

} // namespace outpost
