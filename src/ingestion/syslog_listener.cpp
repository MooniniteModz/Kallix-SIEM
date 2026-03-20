#include "ingestion/syslog_listener.h"
#include "common/logger.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace outpost {

SyslogListener::SyslogListener(RingBuffer<>& buffer, const SyslogConfig& config)
    : buffer_(buffer), config_(config) {}

SyslogListener::~SyslogListener() {
    stop();
}

void SyslogListener::start() {
    if (running_.exchange(true)) return;  // already running

    if (config_.enable_udp) {
        udp_thread_ = std::thread(&SyslogListener::udp_loop, this);
        LOG_INFO("UDP syslog listener starting on {}:{}", config_.bind_address, config_.udp_port);
    }
    if (config_.enable_tcp) {
        tcp_thread_ = std::thread(&SyslogListener::tcp_loop, this);
        LOG_INFO("TCP syslog listener starting on {}:{}", config_.bind_address, config_.tcp_port);
    }
}

void SyslogListener::stop() {
    if (!running_.exchange(false)) return;

    // Close sockets to unblock recv/accept
    if (udp_fd_ >= 0) { ::close(udp_fd_); udp_fd_ = -1; }
    if (tcp_fd_ >= 0) { ::close(tcp_fd_); tcp_fd_ = -1; }

    if (udp_thread_.joinable()) udp_thread_.join();
    if (tcp_thread_.joinable()) tcp_thread_.join();
    for (auto& t : tcp_client_threads_) {
        if (t.joinable()) t.join();
    }
    tcp_client_threads_.clear();

    LOG_INFO("Syslog listeners stopped. UDP received: {}, TCP received: {}",
             udp_received_.load(), tcp_received_.load());
}

// ── UDP Listener ──

void SyslogListener::udp_loop() {
    udp_fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd_ < 0) {
        LOG_ERROR("Failed to create UDP socket: {}", strerror(errno));
        return;
    }

    // Allow address reuse
    int opt = 1;
    ::setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Increase receive buffer to 4 MB to handle bursts
    int rcvbuf = 4 * 1024 * 1024;
    ::setsockopt(udp_fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.udp_port);
    inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);

    if (::bind(udp_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind UDP socket to {}:{} - {}", 
                  config_.bind_address, config_.udp_port, strerror(errno));
        ::close(udp_fd_);
        udp_fd_ = -1;
        return;
    }

    LOG_INFO("UDP syslog listener bound to {}:{}", config_.bind_address, config_.udp_port);

    char buf[RawMessage::MAX_SIZE];
    sockaddr_in sender{};
    socklen_t sender_len;

    while (running_.load(std::memory_order_relaxed)) {
        sender_len = sizeof(sender);

        // Use poll to allow periodic running_ checks
        pollfd pfd{udp_fd_, POLLIN, 0};
        int ret = ::poll(&pfd, 1, 100);  // 100ms timeout
        if (ret <= 0) continue;

        ssize_t n = ::recvfrom(udp_fd_, buf, sizeof(buf) - 1, 0,
                               reinterpret_cast<sockaddr*>(&sender), &sender_len);
        if (n <= 0) continue;

        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender.sin_addr, sender_ip, sizeof(sender_ip));

        RawMessage msg;
        msg.set(buf, static_cast<size_t>(n), config_.udp_port, sender_ip);

        if (!buffer_.try_push(msg)) {
            buffer_.record_drop();
            // UDP drops are expected under backpressure
        }

        udp_received_.fetch_add(1, std::memory_order_relaxed);
    }
}

// ── TCP Listener ──

void SyslogListener::tcp_loop() {
    tcp_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd_ < 0) {
        LOG_ERROR("Failed to create TCP socket: {}", strerror(errno));
        return;
    }

    int opt = 1;
    ::setsockopt(tcp_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.tcp_port);
    inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr);

    if (::bind(tcp_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind TCP socket to {}:{} - {}",
                  config_.bind_address, config_.tcp_port, strerror(errno));
        ::close(tcp_fd_);
        tcp_fd_ = -1;
        return;
    }

    if (::listen(tcp_fd_, config_.tcp_backlog) < 0) {
        LOG_ERROR("TCP listen failed: {}", strerror(errno));
        ::close(tcp_fd_);
        tcp_fd_ = -1;
        return;
    }

    LOG_INFO("TCP syslog listener bound to {}:{}", config_.bind_address, config_.tcp_port);

    while (running_.load(std::memory_order_relaxed)) {
        // Poll for new connections with timeout
        pollfd pfd{tcp_fd_, POLLIN, 0};
        int ret = ::poll(&pfd, 1, 100);
        if (ret <= 0) continue;

        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(tcp_fd_, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) continue;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        LOG_DEBUG("TCP syslog client connected: {}", client_ip);

        // Spawn a handler thread per client
        // (For production, this should use a thread pool or epoll, but
        //  for the number of syslog sources at UPT scale this is fine)
        tcp_client_threads_.emplace_back(
            &SyslogListener::handle_tcp_client, this, client_fd, std::string(client_ip));
    }
}

void SyslogListener::handle_tcp_client(int client_fd, const std::string& client_addr) {
    // TCP syslog: newline-delimited or octet-counted (RFC 5425).
    // We support newline-delimited (most common for FortiGate/generic syslog).

    char buf[RawMessage::MAX_SIZE];
    std::string line_buffer;
    line_buffer.reserve(4096);

    while (running_.load(std::memory_order_relaxed)) {
        pollfd pfd{client_fd, POLLIN, 0};
        int ret = ::poll(&pfd, 1, 100);
        if (ret < 0) break;
        if (ret == 0) continue;

        ssize_t n = ::recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;  // client disconnected or error

        // Scan for newline-delimited messages
        for (ssize_t i = 0; i < n; ++i) {
            if (buf[i] == '\n') {
                if (!line_buffer.empty()) {
                    RawMessage msg;
                    msg.set(line_buffer.data(), line_buffer.size(),
                            config_.tcp_port, client_addr.c_str());

                    if (!buffer_.try_push(msg)) {
                        buffer_.record_drop();
                    }
                    tcp_received_.fetch_add(1, std::memory_order_relaxed);
                    line_buffer.clear();
                }
            } else {
                line_buffer += buf[i];
                // Safety: don't let a single line grow unbounded
                if (line_buffer.size() >= RawMessage::MAX_SIZE - 1) {
                    RawMessage msg;
                    msg.set(line_buffer.data(), line_buffer.size(),
                            config_.tcp_port, client_addr.c_str());
                    if (!buffer_.try_push(msg)) {
                        buffer_.record_drop();
                    }
                    tcp_received_.fetch_add(1, std::memory_order_relaxed);
                    line_buffer.clear();
                }
            }
        }
    }

    ::close(client_fd);
    LOG_DEBUG("TCP syslog client disconnected: {}", client_addr);
}

} // namespace outpost
