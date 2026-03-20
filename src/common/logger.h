#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <memory>
#include <string>

namespace outpost {

/// Initialize the global Outpost logger.
/// Call once at startup before any logging.
void init_logger(const std::string& log_file = "", 
                 spdlog::level::level_enum level = spdlog::level::info);

/// Get the Outpost logger instance
std::shared_ptr<spdlog::logger> get_logger();

} // namespace outpost

// Convenience macros
#define LOG_TRACE(...)    SPDLOG_LOGGER_TRACE(outpost::get_logger(), __VA_ARGS__)
#define LOG_DEBUG(...)    SPDLOG_LOGGER_DEBUG(outpost::get_logger(), __VA_ARGS__)
#define LOG_INFO(...)     SPDLOG_LOGGER_INFO(outpost::get_logger(), __VA_ARGS__)
#define LOG_WARN(...)     SPDLOG_LOGGER_WARN(outpost::get_logger(), __VA_ARGS__)
#define LOG_ERROR(...)    SPDLOG_LOGGER_ERROR(outpost::get_logger(), __VA_ARGS__)
#define LOG_CRITICAL(...) SPDLOG_LOGGER_CRITICAL(outpost::get_logger(), __VA_ARGS__)
