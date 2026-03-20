# Outpost SIEM — Developer Reference

## System Overview

Outpost is a single-binary C++ SIEM with a React frontend. **4,157 lines of C++** across 33 source files, **19 YAML detection rules**, and a **React dashboard**. All components share one process and communicate via lock-free queues and direct function calls — no network hops between internal components.

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           LOG SOURCES                                   │
│  FortiGate (syslog)  ·  Windows (XML/JSON)  ·  M365 (REST API)        │
│  Azure (REST API)    ·  Generic Syslog (RFC 3164/5424)                 │
└────────────┬──────────────────────┬─────────────────────────────────────┘
             │                      │
      ┌──────▼──────┐      ┌───────▼────────┐
      │  SyslogListener  │      │   HttpPoller      │
      │  UDP + TCP       │      │   OAuth2 + REST   │
      └──────┬──────┘      └───────┬────────┘
             │                      │
             └──────┬───────────────┘
                    │
            ┌───────▼───────┐
            │  RingBuffer   │  Lock-free MPSC, 65536 slots
            │  (8KB/slot)   │  Backpressure: drop + count
            └───────┬───────┘
                    │
          ┌─────────▼─────────┐
          │  Parser Workers   │  2 threads (configurable)
          │  (try each parser │  FortiGate → Windows → M365
          │   until match)    │  → Azure → Syslog (catch-all)
          └────┬─────────┬────┘
               │         │
      ┌────────▼──┐  ┌───▼──────────┐
      │  Storage  │  │  RuleEngine  │
      │  Engine   │  │  evaluate()  │
      │  insert() │  │  threshold   │
      └────┬──────┘  │  sequence    │
           │         │  valuelist   │
           │         └──────┬───────┘
           │                │ fire_alert()
           │         ┌──────▼───────┐
           │         │  insert_alert │
           │         └──────┬───────┘
           └────────┬───────┘
                    │
            ┌───────▼───────┐
            │  SQLite + FTS5│  outpost-YYYY-MM-DD.db
            │  WAL mode     │  Daily rotation
            └───────┬───────┘
                    │
            ┌───────▼───────┐
            │   REST API    │  cpp-httplib :8080
            │   /api/*      │  CORS enabled
            └───────┬───────┘
                    │
            ┌───────▼───────┐
            │  React        │  Dashboard + Event Explorer
            │  Frontend     │  Auto-refresh, FTS search
            └───────────────┘
```

---

## Threading Model

| Thread              | File                        | Purpose                                       |
|---------------------|-----------------------------|-----------------------------------------------|
| Main                | `main.cpp`                  | Signal handling, stats loop, shutdown          |
| UDP Listener        | `syslog_listener.cpp`       | poll() + recvfrom() on UDP socket              |
| TCP Listener        | `syslog_listener.cpp`       | poll() + accept(), spawns client handlers      |
| TCP Client (N)      | `syslog_listener.cpp`       | One per TCP client, newline-delimited recv     |
| M365 Poller         | `http_poller.cpp`           | OAuth2 + Management Activity API polling       |
| Azure Poller        | `http_poller.cpp`           | OAuth2 + Activity Log REST API polling         |
| Parser Worker (2)   | `main.cpp:parser_worker()`  | Drain ring buffer → parse → store → evaluate   |
| Flush Worker        | `main.cpp:flush_worker()`   | Periodic storage.flush() every 1 second        |
| API Server          | `server.cpp`                | cpp-httplib listener thread                    |

---

## Directory Structure

```
outpost/
├── CMakeLists.txt              # Build system — FetchContent for all deps
├── config/
│   ├── outpost.yaml            # Main configuration
│   └── rules/                  # Detection rule YAML files
│       ├── fortigate.yaml      #   4 rules (brute force, scanning, sequences)
│       ├── windows.yaml        #   6 rules (RDP, account mgmt, services, sequences)
│       ├── m365.yaml           #   6 rules (token hijack, inbox rules, OAuth, roles)
│       └── azure.yaml          #   3 rules (role assignment, NSG, resource deletion)
├── src/
│   ├── main.cpp                # Entry point, thread orchestration (194 lines)
│   ├── common/
│   │   ├── event.h/cpp         # Common Event Schema struct + JSON serialization
│   │   ├── logger.h/cpp        # spdlog wrapper with console + rotating file
│   │   └── utils.h/cpp         # UUID v4, now_ms(), date strings, ISO 8601
│   ├── ingestion/
│   │   ├── ring_buffer.h       # Lock-free MPSC ring buffer (template, header-only)
│   │   ├── syslog_listener.h/cpp  # UDP + TCP syslog receiver
│   │   └── http_poller.h/cpp   # OAuth2 + REST polling for M365/Azure
│   ├── parser/
│   │   ├── parser.h            # Base parser interface (parse → optional<Event>)
│   │   ├── fortigate_parser.h/cpp  # Key=value syslog parsing
│   │   ├── windows_parser.h/cpp    # XML + JSON Windows event parsing
│   │   ├── m365_parser.h/cpp       # M365 Management Activity API JSON
│   │   ├── azure_parser.h/cpp      # Azure Activity Log JSON
│   │   └── syslog_parser.h/cpp     # Generic RFC 3164/5424 (catch-all)
│   ├── rules/
│   │   ├── rule.h/cpp           # Rule data structures + YAML loader
│   │   └── rule_engine.h/cpp    # Threshold/Sequence/ValueList evaluation
│   ├── storage/
│   │   ├── storage_engine.h/cpp # SQLite writer, query, aggregation, alerts
│   │   └── retention.cpp        # Daily DB cleanup by age
│   └── api/
│       └── server.h/cpp         # REST API endpoints (cpp-httplib)
├── tests/
│   ├── test_ring_buffer.cpp     # 4 tests
│   ├── test_parsers.cpp         # 12 tests (FortiGate, Windows, M365, Azure, Syslog)
│   ├── test_storage.cpp         # 3 tests (init, insert+query, FTS search)
│   └── test_rules.cpp           # 7 tests (load, threshold, grouping, filter, valuelist, sequence, cooldown)
└── frontend/
    └── (React + Vite — outpost-dashboard.jsx)
```

---

## Component Deep Dive

### 1. Ring Buffer (`ingestion/ring_buffer.h`)

The central data structure connecting ingestion to parsing. Heap-allocated to avoid stack overflow (each slot is ~8KB).

**Key details:**
- Template parameter N must be power of 2 (default 65536)
- MPSC: multiple producers (syslog threads, HTTP poller), single consumer pattern
- `try_push()` returns false on full → caller records drop
- `try_pop()` returns `std::nullopt` on empty
- Slots use atomic sequence numbers for lock-free coordination
- Head/tail are cache-line aligned (`alignas(64)`) to prevent false sharing

**To modify:** If you need larger messages, change `RawMessage::MAX_SIZE` (currently 8192). If you need more buffer depth, change the template parameter in `main.cpp` where `RingBuffer<>` is instantiated.

### 2. Parsers (`parser/`)

Each parser implements the `Parser` interface:

```cpp
class Parser {
    virtual std::optional<Event> parse(const RawMessage& raw) = 0;
    virtual const char* name() const = 0;
};
```

**Parser order matters** — in `main.cpp` they're tried sequentially, first match wins:
1. FortiGateParser — checks for `logid=` or `devname=`
2. WindowsParser — checks for `<Event` or `"EventID"`
3. M365Parser — checks for `"Operation"` + `"Workload"` or `"CreationTime"`
4. AzureParser — checks for `"operationName"` + `"resourceId"`
5. SyslogParser — accepts everything (catch-all, always last)

**To add a new parser:**
1. Create `parser/myparser.h` and `parser/myparser.cpp`
2. Implement the `Parser` interface
3. Add to `CMakeLists.txt` in the `outpost_lib` source list
4. Add to `main.cpp` parser vector (before SyslogParser)
5. Write tests in `tests/test_parsers.cpp`

### 3. Common Event Schema (`common/event.h`)

Every log normalizes to this struct. This is the contract between parsers, storage, rules, and API.

| Field        | Type              | Notes                                    |
|-------------|-------------------|------------------------------------------|
| event_id    | string (UUID)     | Generated at parse time                  |
| timestamp   | int64 (epoch ms)  | From source; falls back to received_at   |
| received_at | int64 (epoch ms)  | When Outpost received it                 |
| source_type | enum              | FortiGate, Windows, M365, Azure, Syslog  |
| source_host | string            | Originating hostname or IP               |
| severity    | enum (0-7)        | Maps to syslog severity                  |
| category    | enum              | Auth, Network, Endpoint, Cloud, System   |
| action      | string            | Normalized: login_success, deny, etc.    |
| outcome     | enum              | Success, Failure, Unknown                |
| src_ip      | string            | Source IP                                |
| dst_ip      | string            | Destination IP                           |
| src_port    | uint16            |                                          |
| dst_port    | uint16            |                                          |
| user        | string            | Username or UPN                          |
| user_agent  | string            | From M365/Azure events                   |
| resource    | string            | Target file, mailbox, VM, etc.           |
| raw         | string            | Original unparsed log line               |
| metadata    | nlohmann::json    | Source-specific fields (extensible)      |

**To add a field:** Add it to the Event struct in `event.h`, update `event_to_json()` in `event.cpp`, add a column to `create_schema()` in `storage_engine.cpp`, and update the query result parsing.

### 4. Storage Engine (`storage/storage_engine.h/cpp`)

SQLite with daily partitioning. Each day gets its own file: `data/outpost-2026-03-11.db`.

**Write path:** `insert()` → write_buffer_ → `flush()` batches into a single SQL transaction. Flush happens every 1 second or when explicitly called.

**Read path:** Direct SQLite queries. FTS5 index on the `raw` field enables keyword search.

**Key methods:**
- `query(start_ms, end_ms, keyword, limit, offset)` — main event search
- `query_by_id(event_id)` — single event lookup
- `count_by_field(field)` — GROUP BY aggregation (whitelisted fields only)
- `top_values(field, limit)` — top N with count
- `event_timeline(hours)` — hourly histogram
- `insert_alert(alert)` / `get_alerts(limit)` — alert CRUD

**SQLite pragmas set at open:**
- `journal_mode=WAL` — concurrent reads during writes
- `synchronous=NORMAL` — trade durability for speed (acceptable for SIEM)
- `cache_size=-65536` — 64MB page cache
- `temp_store=MEMORY`

**To query across multiple days:** Currently `query()` only searches the current day's DB. To search historical data, you'd ATTACH older databases or iterate over DB files matching the date range. The `current_db()` method handles daily rotation.

### 5. Rule Engine (`rules/rule_engine.h/cpp`)

Evaluates every parsed event against all loaded rules. Three rule types:

**Threshold:** Sliding window per group key. Example: 10 failed logins from same IP in 5 minutes.
- State: `rule_id → group_key → deque<WindowEntry>`
- Expired entries pruned on access and periodically

**Sequence:** Ordered multi-step pattern per group key. Example: failed login then success from same IP.
- State: `rule_id → group_key → SequenceState{current_step, event_ids}`
- Window expiry resets the sequence

**ValueList:** Field value matches a set. Example: source IP in known-bad list.
- No state needed — immediate match

**Alert cooldown:** 5 minutes per rule+group_key combination. Prevents spam when a brute force is ongoing.

**To add a new rule:** Create or edit a YAML file in `config/rules/`. Rules hot-reload on SIGHUP (reload_rules method exists but SIGHUP handler not yet wired — easy to add).

**Rule YAML format:**
```yaml
rules:
  - id: UNIQUE-ID
    name: Human Name
    description: What this detects
    severity: low|medium|high|critical
    type: threshold|sequence|valuelist
    tags: [tag1, tag2]
    filter:
      source_type: fortigate    # optional
      category: auth            # optional
      action: login-failed      # optional
      field: metadata_field     # optional custom field
      value: field_value        # optional match value
    condition:
      # For threshold:
      threshold: 10
      window: 5m                # supports Nm, Nh, Ns
      group_by: src_ip
      # For sequence:
      window: 10m
      group_by: user
      steps:
        - label: Step 1
          filter: { action: login_failure }
        - label: Step 2
          filter: { action: login_success }
      # For valuelist:
      field: src_ip
      values: ["1.2.3.4", "5.6.7.8"]
```

### 6. REST API (`api/server.h/cpp`)

All endpoints return JSON. CORS is enabled for all origins (dev mode).

| Endpoint                  | Method | Returns                                    |
|--------------------------|--------|---------------------------------------------|
| `/api/health`            | GET    | Status, version, uptime, buffer/event stats |
| `/api/events`            | GET    | Events with ?q=&start=&end=&limit=&offset= |
| `/api/events/:id`        | GET    | Single event by UUID                        |
| `/api/stats`             | GET    | Today's event count, buffer, drops, uptime  |
| `/api/stats/sources`     | GET    | Event count by source_type                  |
| `/api/stats/severity`    | GET    | Event count by severity                     |
| `/api/stats/categories`  | GET    | Event count by category                     |
| `/api/stats/top-ips`     | GET    | Top source IPs (?limit=N)                   |
| `/api/stats/top-users`   | GET    | Top users (?limit=N)                        |
| `/api/stats/top-actions` | GET    | Top actions (?limit=N)                      |
| `/api/stats/timeline`    | GET    | Hourly event histogram (?hours=N)           |

**To add an endpoint:** Add a `server_.Get(...)` or `server_.Post(...)` call in `setup_routes()` in `server.cpp`. The storage engine reference is available as `storage_`.

### 7. React Frontend (`outpost-dashboard.jsx`)

Single-file React component using Tailwind and Recharts. Connects to the API at `http://localhost:8080`.

**Key components:**
- `OutpostDashboard` — main app, manages tabs (dashboard/events) and search state
- `StatCard` — metric display with icon
- `Timeline` — Recharts LineChart for hourly event volume
- `BreakdownChart` — horizontal bar charts for source/severity/category/top-N
- `EventsTable` — scrollable event list with expandable rows
- `EventRow` — individual event with expand/collapse for full detail + raw log + metadata

**To modify the frontend:**
- Change `API` constant at the top to point to a different backend
- Colors are in the `C` object and `severityColors`/`sourceColors` maps
- Auto-refresh intervals are in `useApi()` calls (second parameter, milliseconds)
- Add new API endpoints by creating new `useApi()` hooks

---

## Build & Dependencies

### System requirements
- CMake 3.20+, GCC 13+ or Clang 16+ (C++20)
- `libsqlite3-dev`, `libssl-dev` (for HTTPS), `pkg-config`

### C++ dependencies (auto-fetched via CMake FetchContent)
| Library       | Version | Purpose                          |
|--------------|---------|----------------------------------|
| nlohmann/json | 3.11.3  | JSON parsing/serialization       |
| spdlog        | 1.14.1  | Structured logging               |
| yaml-cpp      | 0.8.0   | Config and rule YAML parsing     |
| cpp-httplib   | 0.16.3  | HTTP server + client             |
| GoogleTest    | 1.14.0  | Unit testing                     |

### Build commands
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
./outpost_tests      # 30 tests
./outpost            # run from project root for rules to load
```

---

## Data Flow Summary

```
1. Raw bytes arrive   →  SyslogListener.udp_loop() / HttpPoller.m365_poll_loop()
2. RawMessage created →  {data[8192], length, source_port, source_addr}
3. Ring buffer push   →  try_push() returns false if full (drop counted)
4. Parser worker pop  →  try_pop() in a spin loop (100μs sleep on empty)
5. Parser chain       →  FortiGate → Windows → M365 → Azure → Syslog
6. Event created      →  Common schema struct with UUID, timestamps, fields
7. Storage insert     →  Buffered; flushed in batched SQL transaction
8. Rule evaluation    →  All 19 rules checked against the event
9. Alert (maybe)      →  Written to alerts table, logged as WARNING
10. API query         →  Frontend polls /api/* endpoints every 5-10 seconds
```

---

## Quick Reference: Adding Things

| I want to...                  | Files to touch                                                |
|-------------------------------|---------------------------------------------------------------|
| Add a new log source parser   | New `parser/x_parser.h/cpp`, `CMakeLists.txt`, `main.cpp`    |
| Add a field to Event schema   | `common/event.h`, `event.cpp`, `storage_engine.cpp` (schema + query) |
| Add a detection rule          | New or existing YAML in `config/rules/`                       |
| Add a new rule type           | `rules/rule.h` (enum + config struct), `rule.cpp` (YAML), `rule_engine.cpp` (evaluate) |
| Add an API endpoint           | `api/server.cpp` in `setup_routes()`                          |
| Add a dashboard widget        | `outpost-dashboard.jsx` — new `useApi()` hook + component     |
| Change syslog port            | `main.cpp` or `config/outpost.yaml` (config loader not yet wired) |
| Change storage location       | `main.cpp` → `storage_config.data_dir`                       |
| Add TLS to syslog             | `syslog_listener.cpp` — add OpenSSL socket wrapping           |
| Add API authentication        | `api/server.cpp` — add auth middleware in `set_pre_routing_handler` |
