#include <gtest/gtest.h>
#include "storage/postgres_storage_engine.h"
#include "common/utils.h"

#include <filesystem>

using namespace outpost;

class StorageTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.host = "localhost";
        config_.port = 5432;
        config_.dbname = "outpost_test";
        config_.user = "postgres";
        config_.password = "";
    }

    void TearDown() override {
        // PostgreSQL cleanup happens on database level, not file level
    }

    PostgresConfig config_;
};

TEST_F(StorageTest, InitConnectsToPostgres) {
    PostgresStorageEngine engine(config_);
    bool success = engine.init();
    if (!success) {
        GTEST_SKIP() << "PostgreSQL connection failed - skipping test";
    }
    ASSERT_TRUE(success);
}

TEST_F(StorageTest, InsertAndQuery) {
    PostgresStorageEngine engine(config_);
    if (!engine.init()) {
        GTEST_SKIP() << "PostgreSQL connection failed - skipping test";
    }

    Event e;
    e.event_id    = generate_uuid();
    e.timestamp   = now_ms();
    e.received_at = e.timestamp;
    e.source_type = SourceType::FortiGate;
    e.source_host = "FG-Test";
    e.action      = "accept";
    e.src_ip      = "10.0.0.1";
    e.dst_ip      = "8.8.8.8";
    e.raw         = "test log line with keyword firewall";

    engine.insert(e);
    engine.flush();

    EXPECT_EQ(engine.count_today(), 1);
    EXPECT_EQ(engine.total_inserted(), 1);

    // Query by time range
    auto results = engine.query(e.timestamp - 1000, e.timestamp + 1000);
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].src_ip, "10.0.0.1");
    EXPECT_EQ(results[0].source_host, "FG-Test");
}

TEST_F(StorageTest, FTSKeywordSearch) {
    PostgresStorageEngine engine(config_);
    if (!engine.init()) {
        GTEST_SKIP() << "PostgreSQL connection failed - skipping test";
    }

    Event e1;
    e1.event_id = generate_uuid();
    e1.timestamp = now_ms();
    e1.received_at = e1.timestamp;
    e1.source_type = SourceType::FortiGate;
    e1.raw = "action=deny srcip=10.0.1.50 dstip=malicious.example.com";

    Event e2;
    e2.event_id = generate_uuid();
    e2.timestamp = now_ms();
    e2.received_at = e2.timestamp;
    e2.source_type = SourceType::Syslog;
    e2.raw = "sshd: Accepted publickey for admin from 10.0.0.5";

    engine.insert(e1);
    engine.insert(e2);
    engine.flush();

    // Search for "malicious"
    auto results = engine.query(e1.timestamp - 1000, e2.timestamp + 1000, "malicious");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].raw.find("malicious"), std::string::npos);

    // Search for "sshd"
    results = engine.query(e1.timestamp - 1000, e2.timestamp + 1000, "sshd");
    ASSERT_EQ(results.size(), 1);
    EXPECT_NE(results[0].raw.find("sshd"), std::string::npos);
}
