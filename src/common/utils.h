#pragma once

#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <string>
#include <httplib.h>

namespace outpost {

/// Extract a named cookie value from a request's Cookie header
inline std::string get_cookie(const httplib::Request& req, const std::string& name) {
    const auto& hdr = req.get_header_value("Cookie");
    if (hdr.empty()) return "";
    std::istringstream ss(hdr);
    std::string seg;
    while (std::getline(ss, seg, ';')) {
        auto s = seg.find_first_not_of(' ');
        if (s == std::string::npos) continue;
        seg = seg.substr(s);
        auto eq = seg.find('=');
        if (eq == std::string::npos) continue;
        if (seg.substr(0, eq) == name) return seg.substr(eq + 1);
    }
    return "";
}

/// Extract session token from Bearer Authorization header OR kallix_session cookie
inline std::string extract_session_token(const httplib::Request& req) {
    auto it = req.headers.find("Authorization");
    if (it != req.headers.end()) {
        const auto& val = it->second;
        if (val.size() > 7 && val.substr(0, 7) == "Bearer ") return val.substr(7);
    }
    return get_cookie(req, "kallix_session");
}

/// Get current time and set as epoch milliseconds
inline int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

/// Generate a UUID v4
inline std::string generate_uuid() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static thread_local std::uniform_int_distribution<uint64_t> dist;

    uint64_t hi = dist(rng);
    uint64_t lo = dist(rng);

    // Set version 4 bits
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    // Set variant bits
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(8)  << ((hi >> 32) & 0xFFFFFFFF) << '-';
    ss << std::setw(4)  << ((hi >> 16) & 0xFFFF) << '-';
    ss << std::setw(4)  << (hi & 0xFFFF) << '-';
    ss << std::setw(4)  << ((lo >> 48) & 0xFFFF) << '-';
    ss << std::setw(12) << (lo & 0xFFFFFFFFFFFFULL);
    return ss.str();
}

/// Get today's date as YYYY-MM-DD string (for daily DB partitioning)
inline std::string today_date_string() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&time, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d");
    return ss.str();
}

/// Convert epoch ms to ISO 8601 string
inline std::string epoch_ms_to_iso(int64_t ms) {
    auto seconds = ms / 1000;
    auto remainder = ms % 1000;
    std::tm tm{};
    gmtime_r(&seconds, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << remainder << 'Z';
    return ss.str();
}

} // namespace outpost
