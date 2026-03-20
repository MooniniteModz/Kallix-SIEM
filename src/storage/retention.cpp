#include "common/logger.h"
#include <filesystem>
#include <string>
#include <regex>

namespace outpost {

/// Delete database files older than retention_days
void enforce_retention(const std::string& data_dir, int retention_days) {
    namespace fs = std::filesystem;

    auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24 * retention_days);
    auto cutoff_time = std::chrono::system_clock::to_time_t(cutoff);

    std::regex db_pattern(R"(outpost-(\d{4}-\d{2}-\d{2})\.db.*)");

    for (const auto& entry : fs::directory_iterator(data_dir)) {
        std::string filename = entry.path().filename().string();
        std::smatch match;
        if (std::regex_match(filename, match, db_pattern)) {
            std::string date_str = match[1].str();
            std::tm tm{};
            std::istringstream ss(date_str);
            ss >> std::get_time(&tm, "%Y-%m-%d");
            if (!ss.fail()) {
                time_t file_time = timegm(&tm);
                if (file_time < cutoff_time) {
                    std::error_code ec;
                    fs::remove(entry.path(), ec);
                    if (!ec) {
                        LOG_INFO("Retention: deleted {}", filename);
                    }
                }
            }
        }
    }
}

} // namespace outpost
