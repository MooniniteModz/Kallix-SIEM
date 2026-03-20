#include "common/logger.h"
#include <vector>

namespace outpost {

static std::shared_ptr<spdlog::logger> s_logger;

void init_logger(const std::string& log_file, spdlog::level::level_enum level) {
    std::vector<spdlog::sink_ptr> sinks;

    // Always log to console with color
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(level);
    sinks.push_back(console_sink);

    // Optionally log to rotating file (10 MB, 5 rotated files)
    if (!log_file.empty()) {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, 10 * 1024 * 1024, 5);
        file_sink->set_level(level);
        sinks.push_back(file_sink);
    }

    s_logger = std::make_shared<spdlog::logger>("outpost", sinks.begin(), sinks.end());
    s_logger->set_level(level);
    s_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%s:%#] %v");
    spdlog::set_default_logger(s_logger);
}

std::shared_ptr<spdlog::logger> get_logger() {
    if (!s_logger) {
        // Fallback if init_logger wasn't called
        init_logger();
    }
    return s_logger;
}

} // namespace outpost
