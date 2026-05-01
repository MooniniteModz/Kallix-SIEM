#include "common/geo_lookup.h"
#include "common/logger.h"

#include <maxminddb.h>
#include <cstring>
#include <arpa/inet.h>

namespace outpost {

static bool is_private_ip(const std::string& ip) {
    struct in_addr addr4{};
    struct in6_addr addr6{};

    if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
        uint32_t a = ntohl(addr4.s_addr);
        return (a >> 24) == 10                          // 10.0.0.0/8
            || (a >> 20) == 0xAC1                       // 172.16.0.0/12
            || (a >> 16) == 0xC0A8                      // 192.168.0.0/16
            || (a >> 24) == 127                         // 127.0.0.0/8
            || (a >> 24) == 169 && ((a >> 16) & 0xFF) == 254; // 169.254.0.0/16
    }
    // IPv6 loopback / link-local / ULA — skip
    if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
        return (addr6.s6_addr[0] == 0xfc || addr6.s6_addr[0] == 0xfd) // ULA fc00::/7
            || (addr6.s6_addr[0] == 0xfe && (addr6.s6_addr[1] & 0xc0) == 0x80); // link-local
    }
    return false;
}

GeoLookup::GeoLookup() : mmdb_(new MMDB_s{}), open_(false) {}

GeoLookup::~GeoLookup() {
    if (open_) MMDB_close(static_cast<MMDB_s*>(mmdb_));
    delete static_cast<MMDB_s*>(mmdb_);
}

bool GeoLookup::open(const std::string& mmdb_path) {
    int status = MMDB_open(mmdb_path.c_str(), MMDB_MODE_MMAP, static_cast<MMDB_s*>(mmdb_));
    if (status != MMDB_SUCCESS) {
        LOG_WARN("GeoIP: could not open '{}': {}", mmdb_path, MMDB_strerror(status));
        return false;
    }
    open_ = true;
    LOG_INFO("GeoIP: loaded '{}'", mmdb_path);
    return true;
}

std::optional<GeoResult> GeoLookup::lookup(const std::string& ip) const {
    if (!open_ || ip.empty()) return std::nullopt;
    if (is_private_ip(ip))    return std::nullopt;

    int gai_error = 0, mmdb_error = 0;
    MMDB_lookup_result_s result = MMDB_lookup_string(
        static_cast<const MMDB_s*>(mmdb_), ip.c_str(), &gai_error, &mmdb_error);

    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry)
        return std::nullopt;

    auto get_double = [&](const char* key1, const char* key2) -> std::optional<double> {
        MMDB_entry_data_s data{};
        if (MMDB_get_value(&result.entry, &data, key1, key2, nullptr) == MMDB_SUCCESS
            && data.has_data && data.type == MMDB_DATA_TYPE_DOUBLE)
            return data.double_value;
        return std::nullopt;
    };
    auto get_string = [&](const char* key1, const char* key2, const char* key3 = nullptr) -> std::string {
        MMDB_entry_data_s data{};
        int rc = key3
            ? MMDB_get_value(&result.entry, &data, key1, key2, key3, nullptr)
            : MMDB_get_value(&result.entry, &data, key1, key2, nullptr);
        if (rc == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING)
            return std::string(data.utf8_string, data.data_size);
        return {};
    };

    auto lat = get_double("location", "latitude");
    auto lng = get_double("location", "longitude");
    if (!lat || !lng) return std::nullopt;

    GeoResult r;
    r.latitude  = *lat;
    r.longitude = *lng;
    r.city      = get_string("city", "names", "en");
    r.country   = get_string("country", "names", "en");
    return r;
}

} // namespace outpost
