#include "storage/postgres_storage_engine.h"
#include "common/event.h"
#include "common/utils.h"

#include <iostream>
#include <random>
#include <vector>
#include <string>
#include <cstdlib>
#include <thread>
#include <chrono>

using namespace outpost;

// ── Fake data pools ──

static const std::vector<std::string> AZURE_OPERATIONS = {
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/publicIPAddresses/write",
    "Microsoft.Network/virtualNetworks/write",
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.Resources/subscriptions/resourceGroups/write",
    "Microsoft.Resources/subscriptions/resourceGroups/delete",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.KeyVault/vaults/secrets/write",
    "Microsoft.Sql/servers/firewallRules/write",
    "Microsoft.Web/sites/write",
    "Microsoft.ContainerService/managedClusters/write",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.ManagedIdentity/userAssignedIdentities/write",
};

static const std::vector<std::string> M365_OPERATIONS = {
    "UserLoggedIn",
    "UserLoginFailed",
    "FileAccessed",
    "FileModified",
    "FileDeleted",
    "FileMalwareDetected",
    "New-InboxRule",
    "Set-Mailbox",
    "Add member to role.",
    "Remove member from role.",
    "Add user.",
    "Update user.",
    "Disable account.",
    "Reset user password.",
    "New-TransportRule",
    "Set-AdminAuditLogConfig",
    "Add-MailboxPermission",
    "Set-CASMailbox",
    "SharePointFileOperation",
    "TeamsMeetingJoined",
};

static const std::vector<std::string> FORTIGATE_ACTIONS = {
    "accept", "deny", "close", "timeout", "ip-conn",
    "dns", "ssl-login-fail", "ssh-auth-fail",
};

static const std::vector<std::string> USERS = {
    "admin@contoso.com", "john.smith@contoso.com", "jane.doe@contoso.com",
    "svc-deploy@contoso.com", "bob.jones@contoso.com", "alice.chen@contoso.com",
    "mike.taylor@contoso.com", "sarah.wilson@contoso.com", "attacker@evil.com",
    "helpdesk@contoso.com", "ciso@contoso.com", "devops@contoso.com",
};

static const std::vector<std::string> SRC_IPS = {
    "10.0.1.15", "10.0.1.22", "10.0.2.100", "192.168.1.50",
    "172.16.0.10", "203.0.113.45", "198.51.100.77", "45.33.32.156",
    "91.189.88.142", "8.8.8.8", "1.1.1.1", "185.220.101.42",
    "104.248.30.5", "10.0.3.200", "10.0.4.50",
};

static const std::vector<std::string> DST_IPS = {
    "10.0.0.1", "10.0.0.5", "10.0.1.1", "10.0.2.1",
    "52.168.112.66", "40.112.72.205", "13.107.42.14",
    "104.215.148.63", "168.63.129.16", "20.190.151.70",
};

static const std::vector<std::string> RESOURCES = {
    "/subscriptions/abc123/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web-server-01",
    "/subscriptions/abc123/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/prod-nsg",
    "/subscriptions/abc123/resourceGroups/dev-rg/providers/Microsoft.Storage/storageAccounts/devdata2026",
    "/subscriptions/abc123/resourceGroups/prod-rg/providers/Microsoft.KeyVault/vaults/prod-keyvault",
    "/subscriptions/abc123/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/prod-sql-01",
    "/subscriptions/abc123/resourceGroups/staging-rg/providers/Microsoft.Web/sites/staging-api",
    "/subscriptions/abc123/resourceGroups/prod-rg/providers/Microsoft.Authorization/roleAssignments/role-001",
    "/subscriptions/abc123/resourceGroups/k8s-rg/providers/Microsoft.ContainerService/managedClusters/prod-aks",
};

static const std::vector<std::string> HOSTNAMES = {
    "DC01.contoso.local", "WEB01.contoso.local", "DB01.contoso.local",
    "EXCH01.contoso.local", "FILE01.contoso.local", "APP01.contoso.local",
};

static const std::vector<std::string> LEVELS = {
    "Informational", "Informational", "Informational", "Warning", "Error", "Critical",
};

static const std::vector<std::string> STATUSES = {
    "Succeeded", "Succeeded", "Succeeded", "Succeeded", "Failed", "Started", "Accepted",
};

static const std::vector<Severity> SEVERITIES = {
    Severity::Info, Severity::Info, Severity::Info, Severity::Warning,
    Severity::Error, Severity::Critical, Severity::Info, Severity::Warning,
};

// ── Random helpers ──

static std::mt19937 rng(std::random_device{}());

template <typename T>
static const T& pick(const std::vector<T>& v) {
    std::uniform_int_distribution<size_t> dist(0, v.size() - 1);
    return v[dist(rng)];
}

static int rand_int(int lo, int hi) {
    std::uniform_int_distribution<int> dist(lo, hi);
    return dist(rng);
}

static int64_t rand_timestamp_last_24h() {
    int64_t now = now_ms();
    int64_t offset = rand_int(0, 86400) * 1000LL;
    return now - offset;
}

// ── Event generators ──

static Event make_azure_event() {
    Event e;
    e.event_id    = generate_uuid();
    e.timestamp   = rand_timestamp_last_24h();
    e.received_at = now_ms();
    e.source_type = SourceType::Azure;
    e.source_host = "management.azure.com";
    e.severity    = pick(SEVERITIES);
    e.action      = pick(AZURE_OPERATIONS);
    e.user        = pick(USERS);
    e.src_ip      = pick(SRC_IPS);
    e.resource    = pick(RESOURCES);

    auto status = pick(STATUSES);
    e.outcome = (status == "Succeeded" || status == "Started" || status == "Accepted")
                    ? Outcome::Success : Outcome::Failure;

    // Categorize
    if (e.action.find("Authorization") != std::string::npos ||
        e.action.find("roleAssignment") != std::string::npos)
        e.category = Category::Auth;
    else if (e.action.find("Network") != std::string::npos)
        e.category = Category::Network;
    else if (e.action.find("Compute") != std::string::npos)
        e.category = Category::Endpoint;
    else
        e.category = Category::Cloud;

    // Build raw JSON similar to real Azure activity log
    nlohmann::json raw_json = {
        {"operationName", e.action},
        {"caller", e.user},
        {"resourceId", e.resource},
        {"status", {{"value", status}}},
        {"level", pick(LEVELS)},
        {"httpRequest", {{"clientIpAddress", e.src_ip}}},
        {"eventTimestamp", std::to_string(e.timestamp)},
        {"subscriptionId", "abc123-def456-ghi789"},
        {"correlationId", generate_uuid()},
    };
    e.raw = raw_json.dump();
    e.metadata = raw_json;

    return e;
}

static Event make_m365_event() {
    Event e;
    e.event_id    = generate_uuid();
    e.timestamp   = rand_timestamp_last_24h();
    e.received_at = now_ms();
    e.source_type = SourceType::M365;
    e.source_host = "manage.office.com";
    e.severity    = pick(SEVERITIES);
    e.action      = pick(M365_OPERATIONS);
    e.user        = pick(USERS);
    e.src_ip      = pick(SRC_IPS);

    bool is_fail = (e.action == "UserLoginFailed" || e.action == "FileMalwareDetected");
    e.outcome = is_fail ? Outcome::Failure : Outcome::Success;

    if (e.action.find("Login") != std::string::npos || e.action.find("Logged") != std::string::npos ||
        e.action.find("role") != std::string::npos || e.action.find("user") != std::string::npos ||
        e.action.find("password") != std::string::npos || e.action.find("account") != std::string::npos)
        e.category = Category::Auth;
    else
        e.category = Category::Cloud;

    std::string workload = "AzureActiveDirectory";
    if (e.action.find("File") != std::string::npos || e.action.find("SharePoint") != std::string::npos)
        workload = "SharePoint";
    else if (e.action.find("Inbox") != std::string::npos || e.action.find("Mailbox") != std::string::npos ||
             e.action.find("Transport") != std::string::npos)
        workload = "Exchange";
    else if (e.action.find("Teams") != std::string::npos)
        workload = "MicrosoftTeams";

    nlohmann::json raw_json = {
        {"Operation", e.action},
        {"UserId", e.user},
        {"Workload", workload},
        {"ClientIP", e.src_ip},
        {"CreationTime", std::to_string(e.timestamp)},
        {"Id", e.event_id},
        {"OrganizationId", "contoso.onmicrosoft.com"},
        {"ResultStatus", is_fail ? "Failed" : "Succeeded"},
    };
    e.raw = raw_json.dump();
    e.metadata = raw_json;

    return e;
}

static Event make_fortigate_event() {
    Event e;
    e.event_id    = generate_uuid();
    e.timestamp   = rand_timestamp_last_24h();
    e.received_at = now_ms();
    e.source_type = SourceType::FortiGate;
    e.source_host = "FGT-" + std::to_string(rand_int(100, 999));
    e.severity    = pick(SEVERITIES);
    e.action      = pick(FORTIGATE_ACTIONS);
    e.src_ip      = pick(SRC_IPS);
    e.dst_ip      = pick(DST_IPS);
    e.src_port    = rand_int(1024, 65535);
    e.dst_port    = rand_int(1, 1024);
    e.category    = Category::Network;
    e.outcome     = (e.action == "accept" || e.action == "close") ? Outcome::Success : Outcome::Failure;

    e.raw = "date=2026-03-21 time=12:00:00 devname=" + e.source_host +
            " type=traffic subtype=forward action=" + e.action +
            " srcip=" + e.src_ip + " dstip=" + e.dst_ip +
            " srcport=" + std::to_string(e.src_port) +
            " dstport=" + std::to_string(e.dst_port);

    return e;
}

static Event make_windows_event() {
    Event e;
    e.event_id    = generate_uuid();
    e.timestamp   = rand_timestamp_last_24h();
    e.received_at = now_ms();
    e.source_type = SourceType::Windows;
    e.source_host = pick(HOSTNAMES);
    e.severity    = pick(SEVERITIES);
    e.src_ip      = pick(SRC_IPS);
    e.user        = pick(USERS);
    e.category    = Category::Auth;

    int event_ids[] = {4624, 4625, 4648, 4672, 4720, 4732, 7045, 1102};
    int eid = event_ids[rand_int(0, 7)];
    e.action = "EventID:" + std::to_string(eid);
    e.outcome = (eid == 4625) ? Outcome::Failure : Outcome::Success;
    if (eid == 7045) e.category = Category::System;
    if (eid == 1102) { e.category = Category::System; e.severity = Severity::Critical; }

    e.raw = "<Event><System><EventID>" + std::to_string(eid) +
            "</EventID><Computer>" + e.source_host +
            "</Computer></System><EventData><TargetUserName>" + e.user +
            "</TargetUserName><IpAddress>" + e.src_ip +
            "</IpAddress></EventData></Event>";

    return e;
}

static Event make_syslog_event() {
    Event e;
    e.event_id    = generate_uuid();
    e.timestamp   = rand_timestamp_last_24h();
    e.received_at = now_ms();
    e.source_type = SourceType::Syslog;
    e.source_host = pick(HOSTNAMES);
    e.severity    = pick(SEVERITIES);
    e.src_ip      = pick(SRC_IPS);
    e.category    = Category::System;
    e.outcome     = Outcome::Unknown;

    std::vector<std::string> messages = {
        "sshd[12345]: Accepted publickey for root from " + e.src_ip,
        "sshd[12346]: Failed password for admin from " + e.src_ip,
        "kernel: [UFW BLOCK] IN=eth0 SRC=" + e.src_ip,
        "CRON[9876]: (root) CMD (/usr/bin/backup.sh)",
        "systemd[1]: Started Docker Application Container Engine",
        "sudo: " + pick(USERS) + " : TTY=pts/0 ; PWD=/root ; COMMAND=/bin/bash",
    };
    e.raw = "<14>Mar 21 12:00:00 " + e.source_host + " " + pick(messages);
    e.action = "syslog";

    return e;
}

// ── Main ──

int main(int argc, char* argv[]) {
    int total_events = 500;
    if (argc > 1) total_events = std::atoi(argv[1]);

    // Connect to PostgreSQL
    PostgresConfig pg_config;
    pg_config.host     = std::getenv("PGHOST")     ? std::getenv("PGHOST")     : "localhost";
    pg_config.port     = std::getenv("PGPORT")     ? std::atoi(std::getenv("PGPORT")) : 5432;
    pg_config.dbname   = std::getenv("PGDATABASE") ? std::getenv("PGDATABASE") : "outpost";
    pg_config.user     = std::getenv("PGUSER")     ? std::getenv("PGUSER")     : "postgres";
    pg_config.password = std::getenv("PGPASSWORD") ? std::getenv("PGPASSWORD") : "";
    pg_config.batch_size = 100;

    PostgresStorageEngine storage(pg_config);
    if (!storage.init()) {
        std::cerr << "Failed to connect to PostgreSQL at "
                  << pg_config.host << ":" << pg_config.port << std::endl;
        return 1;
    }

    std::cout << "Connected to PostgreSQL. Injecting " << total_events << " fake events...\n";

    // Distribution: 30% Azure, 25% M365, 20% FortiGate, 15% Windows, 10% Syslog
    int injected = 0;
    for (int i = 0; i < total_events; ++i) {
        int r = rand_int(1, 100);
        Event e;
        if (r <= 30)      e = make_azure_event();
        else if (r <= 55) e = make_m365_event();
        else if (r <= 75) e = make_fortigate_event();
        else if (r <= 90) e = make_windows_event();
        else              e = make_syslog_event();

        storage.insert(e);
        ++injected;

        if (injected % 100 == 0) {
            storage.flush();
            std::cout << "  Injected " << injected << "/" << total_events << " events\n";
        }
    }

    storage.flush();
    std::cout << "\nDone! Injected " << injected << " events into PostgreSQL.\n";
    std::cout << "  Azure:     ~" << (total_events * 30 / 100) << "\n";
    std::cout << "  M365:      ~" << (total_events * 25 / 100) << "\n";
    std::cout << "  FortiGate: ~" << (total_events * 20 / 100) << "\n";
    std::cout << "  Windows:   ~" << (total_events * 15 / 100) << "\n";
    std::cout << "  Syslog:    ~" << (total_events * 10 / 100) << "\n";
    std::cout << "\nStart the backend (build/outpost) and frontend (npm run dev) to view.\n";

    return 0;
}
