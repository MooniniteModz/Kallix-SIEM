#pragma once

#include <atomic>
#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <string>

namespace outpost {

/// ────────────────────────────────────────────────────────────────
/// RawMessage: what the ingestion layer produces and parsers consume.
/// Fixed-size struct that lives in the ring buffer slots.
/// ────────────────────────────────────────────────────────────────
struct RawMessage {
    static constexpr size_t MAX_SIZE = 8192;  // max syslog message + overhead

    char     data[MAX_SIZE];
    uint16_t length = 0;
    uint16_t source_port = 0;   // which listener port received this
    char     source_addr[46];   // sender IP (INET6_ADDRSTRLEN)
    char     source_hint[24];   // source type hint from connector (e.g. "unifi", "azure")

    void set(const char* buf, size_t len, uint16_t port, const char* addr,
             const char* hint = nullptr) {
        length = static_cast<uint16_t>(len < MAX_SIZE ? len : MAX_SIZE - 1);
        std::memcpy(data, buf, length);
        data[length] = '\0';
        source_port = port;
        if (addr) {
            std::strncpy(source_addr, addr, sizeof(source_addr) - 1);
            source_addr[sizeof(source_addr) - 1] = '\0';
        } else {
            source_addr[0] = '\0';
        }
        if (hint) {
            std::strncpy(source_hint, hint, sizeof(source_hint) - 1);
            source_hint[sizeof(source_hint) - 1] = '\0';
        } else {
            source_hint[0] = '\0';
        }
    }

    std::string as_string() const { return std::string(data, length); }
};

/// ────────────────────────────────────────────────────────────────
/// RingBuffer: bounded, lock-free, multi-producer single-consumer.
///
/// Uses a simple spinlock-free approach:
///   - Each slot has a sequence number
///   - Producers CAS to claim a slot, then write data, then publish
///   - Consumer reads published slots in order
///
/// Template parameter N must be a power of 2.
/// ────────────────────────────────────────────────────────────────
template <size_t N = 65536>
class RingBuffer {
    static_assert((N & (N - 1)) == 0, "N must be a power of 2");

public:
    RingBuffer() : slots_(new Slot[N]) {
        for (size_t i = 0; i < N; ++i) {
            slots_[i].sequence.store(i, std::memory_order_relaxed);
        }
        head_.store(0, std::memory_order_relaxed);
        tail_.store(0, std::memory_order_relaxed);
    }

    /// Try to push a message. Returns false if buffer is full (backpressure).
    /// Thread-safe for multiple producers.
    bool try_push(const RawMessage& msg) {
        size_t head = head_.load(std::memory_order_relaxed);

        for (;;) {
            Slot& slot = slots_[head & MASK];
            size_t seq = slot.sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(head);

            if (diff == 0) {
                // Slot is available; try to claim it
                if (head_.compare_exchange_weak(head, head + 1,
                        std::memory_order_relaxed, std::memory_order_relaxed)) {
                    // Claimed. Write data and publish.
                    slot.message = msg;
                    slot.sequence.store(head + 1, std::memory_order_release);
                    return true;
                }
                // CAS failed, another producer claimed it. head has been reloaded, retry.
            } else if (diff < 0) {
                // Buffer is full
                return false;
            } else {
                // Slot was already claimed by another producer; reload head
                head = head_.load(std::memory_order_relaxed);
            }
        }
    }

    /// Try to pop a message. Returns nullopt if buffer is empty.
    /// Thread-safe for multiple consumers.
    std::optional<RawMessage> try_pop() {
        size_t tail = tail_.load(std::memory_order_relaxed);

        for (;;) {
            Slot& slot = slots_[tail & MASK];
            size_t seq = slot.sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(tail + 1);

            if (diff == 0) {
                // Data is ready; try to claim this slot
                if (tail_.compare_exchange_weak(tail, tail + 1,
                        std::memory_order_relaxed, std::memory_order_relaxed)) {
                    // Claimed. Copy data then release slot.
                    RawMessage msg = slot.message;
                    slot.sequence.store(tail + N, std::memory_order_release);
                    return msg;
                }
                // CAS failed, another consumer claimed it. tail reloaded, retry.
            } else if (diff < 0) {
                // Empty
                return std::nullopt;
            } else {
                // Slot not yet published; reload tail
                tail = tail_.load(std::memory_order_relaxed);
            }
        }
    }

    /// Approximate count of items in the buffer
    size_t size_approx() const {
        size_t h = head_.load(std::memory_order_relaxed);
        size_t t = tail_.load(std::memory_order_relaxed);
        return h >= t ? h - t : 0;
    }

    size_t capacity() const { return N; }

    /// Stats
    uint64_t drop_count() const { return drops_.load(std::memory_order_relaxed); }
    void     record_drop()      { drops_.fetch_add(1, std::memory_order_relaxed); }

private:
    static constexpr size_t MASK = N - 1;

    struct Slot {
        std::atomic<size_t> sequence;
        RawMessage          message;
    };

    // Pad to avoid false sharing between head and tail
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
    alignas(64) std::atomic<uint64_t> drops_{0};
    std::unique_ptr<Slot[]> slots_;
};

} // namespace outpost
