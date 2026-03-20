#include <gtest/gtest.h>
#include "parser/fortigate_parser.h"
#include "parser/windows_parser.h"
#include "parser/m365_parser.h"
#include "parser/azure_parser.h"
#include "parser/syslog_parser.h"

using namespace outpost;

TEST(FortiGateParserTest, ParsesKVLog) {
    FortiGateParser parser;

    RawMessage msg;
    const char* log = R"(date=2026-03-11 time=10:30:00 logid="0001000014" type="traffic" subtype="forward" level="notice" srcip=10.0.1.50 srcport=54321 dstip=8.8.8.8 dstport=443 action="accept" devname="FG-Office")";
    msg.set(log, std::strlen(log), 514, "10.0.0.1");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->source_type, SourceType::FortiGate);
    EXPECT_EQ(event->source_host, "FG-Office");
    EXPECT_EQ(event->src_ip, "10.0.1.50");
    EXPECT_EQ(event->dst_ip, "8.8.8.8");
    EXPECT_EQ(event->src_port, 54321);
    EXPECT_EQ(event->dst_port, 443);
    EXPECT_EQ(event->action, "accept");
    EXPECT_EQ(event->outcome, Outcome::Success);
    EXPECT_EQ(event->category, Category::Network);
    EXPECT_EQ(event->severity, Severity::Notice);
    EXPECT_FALSE(event->event_id.empty());
}

TEST(FortiGateParserTest, RejectsNonFortiGate) {
    FortiGateParser parser;

    RawMessage msg;
    const char* log = "<134>Mar 11 10:30:00 myhost sshd[1234]: Accepted password for user1";
    msg.set(log, std::strlen(log), 514, "10.0.0.1");

    auto event = parser.parse(msg);
    EXPECT_FALSE(event.has_value());
}

TEST(FortiGateParserTest, ParsesWithSyslogHeader) {
    FortiGateParser parser;

    RawMessage msg;
    const char* log = R"(<134>date=2026-03-11 time=10:30:00 devname="FG-01" logid="0100032001" type="event" subtype="vpn" action="login-failed" srcip=203.0.113.50 user="jsmith")";
    msg.set(log, std::strlen(log), 514, "10.0.0.1");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->action, "login-failed");
    EXPECT_EQ(event->outcome, Outcome::Failure);
    EXPECT_EQ(event->user, "jsmith");
    EXPECT_EQ(event->category, Category::Auth);
}

TEST(SyslogParserTest, ParsesRFC3164) {
    SyslogParser parser;

    RawMessage msg;
    const char* log = "<134>Mar 11 10:30:00 webserver01 nginx: 200 GET /index.html";
    msg.set(log, std::strlen(log), 514, "192.168.1.10");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->source_type, SourceType::Syslog);
    EXPECT_EQ(event->source_host, "webserver01");
    EXPECT_EQ(event->severity, Severity::Info);  // 134 % 8 = 6 (info)
}

TEST(SyslogParserTest, ParsesRFC5424) {
    SyslogParser parser;

    RawMessage msg;
    const char* log = "<165>1 2026-03-11T10:30:00Z myhost myapp 1234 ID42 - This is the message";
    msg.set(log, std::strlen(log), 514, "10.0.0.5");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->source_host, "myhost");
    EXPECT_EQ(event->severity, Severity::Notice);  // 165 % 8 = 5
}

// ── Windows Parser Tests ──

TEST(WindowsParserTest, ParsesXMLLogonSuccess) {
    WindowsParser parser;

    RawMessage msg;
    const char* xml = R"(<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4624</EventID>
            <Level>0</Level>
            <TimeCreated SystemTime="2026-03-11T10:30:00.000000Z"/>
            <Computer>DC01.upt1.local</Computer>
            <Channel>Security</Channel>
            <Keywords>0x8020000000000000</Keywords>
        </System>
        <EventData>
            <Data Name="TargetUserName">cmoore</Data>
            <Data Name="TargetDomainName">UPT1</Data>
            <Data Name="LogonType">10</Data>
            <Data Name="IpAddress">10.0.1.50</Data>
            <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
        </EventData>
    </Event>)";
    msg.set(xml, std::strlen(xml), 514, "10.0.0.10");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->source_type, SourceType::Windows);
    EXPECT_EQ(event->source_host, "DC01.upt1.local");
    EXPECT_EQ(event->user, "cmoore");
    EXPECT_EQ(event->src_ip, "10.0.1.50");
    EXPECT_EQ(event->action, "login_success");
    EXPECT_EQ(event->outcome, Outcome::Success);
    EXPECT_EQ(event->category, Category::Auth);
    EXPECT_EQ(event->metadata["EventID"], 4624);
    EXPECT_EQ(event->metadata["LogonType"], "10");
}

TEST(WindowsParserTest, ParsesLoginFailure) {
    WindowsParser parser;

    RawMessage msg;
    const char* xml = R"(<Event>
        <System>
            <EventID>4625</EventID>
            <TimeCreated SystemTime="2026-03-11T11:00:00.000Z"/>
            <Computer>RDS01.upt1.local</Computer>
            <Keywords>0x8010000000000000</Keywords>
        </System>
        <EventData>
            <Data Name="TargetUserName">admin</Data>
            <Data Name="IpAddress">203.0.113.50</Data>
        </EventData>
    </Event>)";
    msg.set(xml, std::strlen(xml), 514, "10.0.0.20");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->action, "login_failure");
    EXPECT_EQ(event->outcome, Outcome::Failure);
    EXPECT_EQ(event->user, "admin");
    EXPECT_EQ(event->src_ip, "203.0.113.50");
}

TEST(WindowsParserTest, ParsesServiceInstall) {
    WindowsParser parser;

    RawMessage msg;
    const char* xml = R"(<Event>
        <System>
            <EventID>7045</EventID>
            <TimeCreated SystemTime="2026-03-11T12:00:00.000Z"/>
            <Computer>WS01.upt1.local</Computer>
        </System>
        <EventData>
            <Data Name="ServiceName">SuspiciousService</Data>
            <Data Name="SubjectUserName">SYSTEM</Data>
        </EventData>
    </Event>)";
    msg.set(xml, std::strlen(xml), 514, "10.0.0.30");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->action, "service_installed");
    EXPECT_EQ(event->category, Category::Endpoint);
    EXPECT_EQ(event->resource, "SuspiciousService");
}

TEST(WindowsParserTest, RejectsNonWindowsEvent) {
    WindowsParser parser;

    RawMessage msg;
    const char* log = "date=2026-03-11 time=10:00:00 logid=\"001\" type=\"traffic\"";
    msg.set(log, std::strlen(log), 514, "10.0.0.1");

    EXPECT_FALSE(parser.parse(msg).has_value());
}

// ── M365 Parser Tests ──

TEST(M365ParserTest, ParsesUserLoggedIn) {
    M365Parser parser;

    RawMessage msg;
    std::string json = R"JSON({
        "CreationTime": "2026-03-11T10:30:00",
        "Operation": "UserLoggedIn",
        "Workload": "AzureActiveDirectory",
        "UserId": "jsmith@drive4upt.com",
        "ClientIP": "203.0.113.100:54321",
        "ResultStatus": "Succeeded",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "ObjectId": "00000003-0000-0ff1-ce00-000000000000"
    })JSON";
    msg.set(json.c_str(), json.size(), 443, "api.microsoft.com");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->source_type, SourceType::M365);
    EXPECT_EQ(event->user, "jsmith@drive4upt.com");
    EXPECT_EQ(event->src_ip, "203.0.113.100");  // port stripped
    EXPECT_EQ(event->action, "login_success");
    EXPECT_EQ(event->outcome, Outcome::Success);
    EXPECT_EQ(event->category, Category::Auth);
    EXPECT_FALSE(event->user_agent.empty());
}

TEST(M365ParserTest, ParsesInboxRuleCreation) {
    M365Parser parser;

    RawMessage msg;
    std::string json = R"({
        "CreationTime": "2026-03-11T14:00:00",
        "Operation": "New-InboxRule",
        "Workload": "Exchange",
        "UserId": "compromised@drive4upt.com",
        "ClientIP": "198.51.100.50",
        "ResultStatus": "True"
    })";
    msg.set(json.c_str(), json.size(), 443, "api.microsoft.com");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->action, "inbox_rule_created");
    EXPECT_EQ(event->category, Category::Cloud);
}

TEST(M365ParserTest, ParsesRoleAssignment) {
    M365Parser parser;

    RawMessage msg;
    std::string json = R"({
        "CreationTime": "2026-03-11T15:00:00",
        "Operation": "Add member to role.",
        "Workload": "AzureActiveDirectory",
        "UserId": "attacker@external.com",
        "ClientIP": "198.51.100.100",
        "ResultStatus": "Succeeded",
        "Target": [{"ID": "Global Administrator", "Type": 2}]
    })";
    msg.set(json.c_str(), json.size(), 443, "api.microsoft.com");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->action, "role_assignment");
    EXPECT_EQ(event->category, Category::Auth);
    EXPECT_EQ(event->resource, "Global Administrator");
}

TEST(M365ParserTest, RejectsNonM365) {
    M365Parser parser;

    RawMessage msg;
    const char* log = "date=2026-03-11 time=10:00:00 logid=\"001\" type=\"traffic\"";
    msg.set(log, std::strlen(log), 514, "10.0.0.1");

    EXPECT_FALSE(parser.parse(msg).has_value());
}

// ── Azure Parser Tests ──

TEST(AzureParserTest, ParsesRoleAssignment) {
    AzureParser parser;

    RawMessage msg;
    std::string json = R"({
        "operationName": "Microsoft.Authorization/roleAssignments/write",
        "caller": "admin@drive4upt.com",
        "eventTimestamp": "2026-03-11T16:00:00Z",
        "resourceId": "/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Authorization/roleAssignments/def-456",
        "status": {"value": "Succeeded"},
        "level": "Informational",
        "httpRequest": {"clientIpAddress": "10.0.1.100"}
    })";
    msg.set(json.c_str(), json.size(), 443, "management.azure.com");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->source_type, SourceType::Azure);
    EXPECT_EQ(event->user, "admin@drive4upt.com");
    EXPECT_EQ(event->src_ip, "10.0.1.100");
    EXPECT_EQ(event->outcome, Outcome::Success);
    EXPECT_EQ(event->category, Category::Auth);
    EXPECT_EQ(event->metadata["SubscriptionId"], "abc-123");
}

TEST(AzureParserTest, ParsesNSGChange) {
    AzureParser parser;

    RawMessage msg;
    std::string json = R"({
        "operationName": "Microsoft.Network/networkSecurityGroups/write",
        "caller": "devops@drive4upt.com",
        "eventTimestamp": "2026-03-11T17:00:00Z",
        "resourceId": "/subscriptions/abc-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
        "status": {"value": "Succeeded"},
        "level": "Warning"
    })";
    msg.set(json.c_str(), json.size(), 443, "management.azure.com");

    auto event = parser.parse(msg);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->category, Category::Network);
    EXPECT_EQ(event->severity, Severity::Warning);
}

TEST(AzureParserTest, RejectsNonAzure) {
    AzureParser parser;

    RawMessage msg;
    std::string json = R"({"Operation": "UserLoggedIn", "Workload": "AzureActiveDirectory"})";
    msg.set(json.c_str(), json.size(), 443, "manage.office.com");

    EXPECT_FALSE(parser.parse(msg).has_value());
}
