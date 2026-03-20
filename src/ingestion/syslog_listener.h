#pragma once

#include "ingestion/ring_buffer.h"
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace outpost {

/// Configuration for the syslog listener
struct SyslogConfig {
    std::string bind_address = "0.0.0.0";
    uint16_t    udp_port     = 514;
    uint16_t    tcp_port     = 514;
    bool        enable_udp   = true;
    bool        enable_tcp   = true;
    int         tcp_backlog  = 64;
    size_t      tcp_max_clients = 256;
};

/// ────────────────────────────────────────────────────────────────
/// SyslogListener: receives syslog messages over UDP and TCP,
/// pushes RawMessage structs into the shared ring buffer.
///
/// Runs listener loops on dedicated threads. Designed to be started
/// once and stopped on shutdown via stop().
/// ────────────────────────────────────────────────────────────────
class SyslogListener {
public:
    explicit SyslogListener(RingBuffer<>& buffer, const SyslogConfig& config = {});
    ~SyslogListener();

    /// Start listener threads (non-blocking, returns immediately)
    void start();

    /// Signal all listener threads to stop and join them
    void stop();

    bool is_running() const { return running_.load(std::memory_order_relaxed); }

    // Stats
    uint64_t udp_received() const { return udp_received_.load(std::memory_order_relaxed); }
    uint64_t tcp_received() const { return tcp_received_.load(std::memory_order_relaxed); }
    uint64_t total_received() const { return udp_received() + tcp_received(); }

private:
    void udp_loop();
    void tcp_loop();
    void handle_tcp_client(int client_fd, const std::string& client_addr);

    RingBuffer<>&   buffer_;
    SyslogConfig    config_;
    std::atomic<bool> running_{false};

    int udp_fd_ = -1;
    int tcp_fd_ = -1;

    std::thread udp_thread_;
    std::thread tcp_thread_;
    std::vector<std::thread> tcp_client_threads_;

    std::atomic<uint64_t> udp_received_{0};
    std::atomic<uint64_t> tcp_received_{0};
};

} // namespace outpost
