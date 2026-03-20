#pragma once

#include "common/event.h"
#include "ingestion/ring_buffer.h"
#include <optional>

namespace outpost {

/// Base parser interface. Each log source has a concrete parser.
class Parser {
public:
    virtual ~Parser() = default;

    /// Parse a raw message into a normalized Event.
    /// Returns nullopt if the message can't be parsed by this parser.
    virtual std::optional<Event> parse(const RawMessage& raw) = 0;

    /// Human-readable name for logging
    virtual const char* name() const = 0;
};

} // namespace outpost
