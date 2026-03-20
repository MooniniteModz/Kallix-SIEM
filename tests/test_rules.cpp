#include <gtest/gtest.h>
#include "rules/rule.h"
#include "rules/rule_engine.h"
#include "storage/postgres_storage_engine.h"
#include "common/utils.h"

#include <filesystem>
#include <fstream>

using namespace outpost;

class RuleEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        data_dir_ = "/tmp/outpost-rule-test-" + std::to_string(now_ms());
        rules_dir_ = data_dir_ + "/rules";
        std::filesystem::create_directories(rules_dir_);

        storage_config_.host = "localhost";
        storage_config_.port = 5432;
        storage_config_.dbname = "outpost_test";
        storage_config_.user = "postgres";
        storage_config_.password = "";

        storage_ = std::make_unique<PostgresStorageEngine>(storage_config_);
        if (!storage_->init()) {
            GTEST_SKIP() << "PostgreSQL connection failed - skipping test";
        }
        engine_ = std::make_unique<RuleEngine>(*storage_);
    }

    void TearDown() override {
        engine_.reset();
        storage_.reset();
        std::filesystem::remove_all(data_dir_);
    }

    void write_rule_file(const std::string& filename, const std::string& content) {
        std::ofstream f(rules_dir_ + "/" + filename);
        f << content;
    }

    Event make_event(SourceType src, const std::string& action,
                     const std::string& src_ip = "10.0.0.1",
                     const std::string& user = "testuser") {
        Event e;
        e.event_id    = generate_uuid();
        e.timestamp   = now_ms();
        e.received_at = e.timestamp;
        e.source_type = src;
        e.source_host = "testhost";
        e.action      = action;
        e.category    = Category::Auth;
        e.src_ip      = src_ip;
        e.user        = user;
        e.raw         = "test event";
        return e;
    }

    std::string data_dir_;
    std::string rules_dir_;
    PostgresConfig storage_config_;
    std::unique_ptr<PostgresStorageEngine> storage_;
    std::unique_ptr<RuleEngine> engine_;
};

TEST_F(RuleEngineTest, LoadsRulesFromYAML) {
    write_rule_file("test.yaml", R"(
rules:
  - id: TEST-001
    name: Test Threshold Rule
    description: Test rule
    severity: high
    type: threshold
    filter:
      source_type: fortigate
      action: login-failed
    condition:
      threshold: 3
      window: 5m
      group_by: src_ip
)");

    engine_->load_rules(rules_dir_);
    EXPECT_EQ(engine_->rule_count(), 1);
}

TEST_F(RuleEngineTest, ThresholdRuleFires) {
    write_rule_file("test.yaml", R"(
rules:
  - id: TEST-THRESH
    name: Threshold Test
    description: Fires after 3 events
    severity: high
    type: threshold
    filter:
      source_type: fortigate
      action: login-failed
    condition:
      threshold: 3
      window_seconds: 300
      group_by: src_ip
)");

    engine_->load_rules(rules_dir_);

    // Send 2 events — should not fire
    for (int i = 0; i < 2; ++i) {
        auto e = make_event(SourceType::FortiGate, "login-failed", "192.168.1.100");
        storage_->insert(e);
        engine_->evaluate(e);
    }
    storage_->flush();
    EXPECT_EQ(engine_->alerts_fired(), 0);

    // Send 3rd event — should fire
    auto e3 = make_event(SourceType::FortiGate, "login-failed", "192.168.1.100");
    storage_->insert(e3);
    engine_->evaluate(e3);
    storage_->flush();
    EXPECT_EQ(engine_->alerts_fired(), 1);

    // Verify alert in storage
    auto alerts = storage_->get_alerts(10);
    ASSERT_EQ(alerts.size(), 1);
    EXPECT_EQ(alerts[0].rule_id, "TEST-THRESH");
    EXPECT_EQ(alerts[0].severity, RuleSeverity::High);
    EXPECT_EQ(alerts[0].event_ids.size(), 3);
}

TEST_F(RuleEngineTest, ThresholdGroupsByField) {
    write_rule_file("test.yaml", R"(
rules:
  - id: TEST-GROUP
    name: Grouped Threshold
    description: Groups by src_ip
    severity: medium
    type: threshold
    filter:
      source_type: fortigate
      action: login-failed
    condition:
      threshold: 2
      window_seconds: 300
      group_by: src_ip
)");

    engine_->load_rules(rules_dir_);

    // IP A: 1 event
    auto e1 = make_event(SourceType::FortiGate, "login-failed", "10.0.0.1");
    engine_->evaluate(e1);

    // IP B: 2 events — should fire for B only
    auto e2 = make_event(SourceType::FortiGate, "login-failed", "10.0.0.2");
    engine_->evaluate(e2);
    auto e3 = make_event(SourceType::FortiGate, "login-failed", "10.0.0.2");
    engine_->evaluate(e3);

    EXPECT_EQ(engine_->alerts_fired(), 1);
}

TEST_F(RuleEngineTest, FilterRejectsNonMatching) {
    write_rule_file("test.yaml", R"(
rules:
  - id: TEST-FILTER
    name: FortiGate Only
    description: Only fires for FortiGate
    severity: low
    type: threshold
    filter:
      source_type: fortigate
      action: login-failed
    condition:
      threshold: 1
      window_seconds: 60
      group_by: src_ip
)");

    engine_->load_rules(rules_dir_);

    // Windows event should NOT trigger the FortiGate rule
    auto e = make_event(SourceType::Windows, "login-failed", "10.0.0.1");
    engine_->evaluate(e);

    EXPECT_EQ(engine_->alerts_fired(), 0);

    // FortiGate event SHOULD trigger
    auto e2 = make_event(SourceType::FortiGate, "login-failed", "10.0.0.5");
    engine_->evaluate(e2);

    EXPECT_EQ(engine_->alerts_fired(), 1);
}

TEST_F(RuleEngineTest, ValueListRuleFires) {
    write_rule_file("test.yaml", R"(
rules:
  - id: TEST-VALUELIST
    name: Known Bad IP
    description: Fires on known malicious IPs
    severity: critical
    type: valuelist
    filter:
      source_type: fortigate
    condition:
      field: src_ip
      values:
        - "198.51.100.1"
        - "203.0.113.50"
)");

    engine_->load_rules(rules_dir_);

    // Normal IP — no alert
    auto e1 = make_event(SourceType::FortiGate, "accept", "10.0.0.1");
    engine_->evaluate(e1);
    EXPECT_EQ(engine_->alerts_fired(), 0);

    // Known bad IP — alert
    auto e2 = make_event(SourceType::FortiGate, "accept", "203.0.113.50");
    engine_->evaluate(e2);
    EXPECT_EQ(engine_->alerts_fired(), 1);
}

TEST_F(RuleEngineTest, SequenceRuleFires) {
    write_rule_file("test.yaml", R"(
rules:
  - id: TEST-SEQ
    name: Fail Then Success
    description: Failed login followed by success
    severity: critical
    type: sequence
    filter:
      source_type: windows
    condition:
      window_seconds: 300
      group_by: user
      steps:
        - label: Failed login
          filter:
            action: login_failure
        - label: Successful login
          filter:
            action: login_success
)");

    engine_->load_rules(rules_dir_);

    // Step 1: failed login
    auto e1 = make_event(SourceType::Windows, "login_failure", "10.0.0.1", "victim");
    engine_->evaluate(e1);
    EXPECT_EQ(engine_->alerts_fired(), 0);

    // Step 2: successful login from same user
    auto e2 = make_event(SourceType::Windows, "login_success", "10.0.0.1", "victim");
    engine_->evaluate(e2);
    EXPECT_EQ(engine_->alerts_fired(), 1);
}

TEST_F(RuleEngineTest, CooldownPreventsRepeatFiring) {
    write_rule_file("test.yaml", R"(
rules:
  - id: TEST-COOL
    name: Cooldown Test
    description: Should not fire twice within cooldown
    severity: low
    type: threshold
    filter:
      source_type: syslog
    condition:
      threshold: 1
      window_seconds: 60
      group_by: src_ip
)");

    engine_->load_rules(rules_dir_);

    // First event fires alert
    auto e1 = make_event(SourceType::Syslog, "test", "10.0.0.1");
    engine_->evaluate(e1);
    EXPECT_EQ(engine_->alerts_fired(), 1);

    // Second event from same IP within cooldown — should NOT fire again
    auto e2 = make_event(SourceType::Syslog, "test", "10.0.0.1");
    engine_->evaluate(e2);
    EXPECT_EQ(engine_->alerts_fired(), 1);  // still 1, not 2
}
