#pragma once

#include <string>
#include <optional>

namespace outpost {

struct GeoResult {
    double      latitude;
    double      longitude;
    std::string city;
    std::string country;
};

// Wraps libmaxminddb. Thread-safe (read-only after open). Call open() once at
// startup with the path to GeoLite2-City.mmdb; lookup() returns nullopt if the
// DB is not loaded, the IP is private/invalid, or has no city record.
class GeoLookup {
public:
    GeoLookup();
    ~GeoLookup();

    // Returns true if the database was loaded successfully.
    bool open(const std::string& mmdb_path);
    bool is_open() const { return open_; }

    std::optional<GeoResult> lookup(const std::string& ip) const;

private:
    void* mmdb_ = nullptr;  // MMDB_s*, opaque to avoid including maxminddb.h in headers
    bool  open_ = false;
};

} // namespace outpost
