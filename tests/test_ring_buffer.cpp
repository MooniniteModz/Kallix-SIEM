#include <gtest/gtest.h>
#include "ingestion/ring_buffer.h"

using namespace outpost;

TEST(RingBufferTest, PushPopSingle) {
    RingBuffer<1024> buf;

    RawMessage msg;
    msg.set("hello", 5, 514, "127.0.0.1");

    ASSERT_TRUE(buf.try_push(msg));
    ASSERT_EQ(buf.size_approx(), 1);

    auto popped = buf.try_pop();
    ASSERT_TRUE(popped.has_value());
    EXPECT_EQ(popped->as_string(), "hello");
    EXPECT_EQ(popped->source_port, 514);
}

TEST(RingBufferTest, EmptyPopReturnsNullopt) {
    RingBuffer<1024> buf;
    EXPECT_FALSE(buf.try_pop().has_value());
}

TEST(RingBufferTest, FillAndDrain) {
    constexpr size_t N = 256;
    RingBuffer<N> buf;

    // Fill completely
    for (size_t i = 0; i < N; ++i) {
        RawMessage msg;
        std::string data = "msg-" + std::to_string(i);
        msg.set(data.c_str(), data.size(), 514, "10.0.0.1");
        ASSERT_TRUE(buf.try_push(msg)) << "Failed to push at index " << i;
    }

    // Buffer should be full
    RawMessage overflow;
    overflow.set("overflow", 8, 514, "10.0.0.1");
    EXPECT_FALSE(buf.try_push(overflow));

    // Drain all
    for (size_t i = 0; i < N; ++i) {
        auto popped = buf.try_pop();
        ASSERT_TRUE(popped.has_value()) << "Failed to pop at index " << i;
        std::string expected = "msg-" + std::to_string(i);
        EXPECT_EQ(popped->as_string(), expected);
    }

    EXPECT_FALSE(buf.try_pop().has_value());
}

TEST(RingBufferTest, DropCounter) {
    RingBuffer<1024> buf;
    buf.record_drop();
    buf.record_drop();
    EXPECT_EQ(buf.drop_count(), 2);
}
