<img width="50" height="50" alt="image" src="https://github.com/user-attachments/assets/72e3ce98-0adb-43a9-a02f-6fb9916f86f3" /> 
##Outpost SIEM

A lightweight, self-hosted SIEM built in C++20 with a React frontend. This project aimed to provide a highly customized SIEM with no cost overhead besides compute.

Outpost ingests logs from syslog, cloud APIs (M365, Azure), and network appliances (FortiGate), normalizes them into a common event format, runs detection rules against the stream, and stores everything in PostgreSQL.

---

## Features

- **Multi-source ingestion** — Syslog (UDP/TCP), Microsoft 365 Management API, Azure Monitor, FortiGate, Windows Event Logs
- **Lock-free ring buffer** — Events flow through a wait-free MPSC buffer between ingestion and storage threads
- **Detection engine** — Threshold, sequence, and value-list rule types with sliding windows and per-group state tracking
- **30+ built-in rules** — Brute force, privilege escalation, log tampering, impossible travel, credential abuse chains, and more
- **Custom rule builder** — Create rules from the web UI; stored in PostgreSQL and hot-loaded into the engine
- **PostgreSQL storage** — Batch inserts, full-text search via `tsvector`, configurable retention
- **REST API** — JSON API for events, alerts, stats, rules, connectors, and user management
- **Session auth** — SHA-256 password hashing via OpenSSL, bearer token sessions, role-based access (admin/analyst/viewer)
- **React dashboard** — Clickable charts that drill down into filtered event views
- **Reporting** — Executive overview, threat analysis, and operational KPI dashboards

## Architecture

```
                    ┌──────────────┐
                    │  Syslog UDP  │
                    │  Syslog TCP  │
                    │  HTTP Poller │ ← M365 / Azure OAuth2
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Ring Buffer │  lock-free, bounded
                    └──────┬───────┘
                           │
                ┌──────────▼──────────┐
                │   Parser Workers    │  FortiGate, Windows, M365,
                │   (N threads)       │  Azure, Syslog → Event
                └──────────┬──────────┘
                           │
              ┌────────────▼────────────┐
              │      Rule Engine        │  threshold / sequence / valuelist
              │  (evaluate per event)   │
              └────────────┬────────────┘
                           │
                    ┌──────▼───────┐
                    │  PostgreSQL  │  events, alerts, users,
                    │              │  connectors, custom rules
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   REST API   │  cpp-httplib
                    │   :8080      │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │    React     │  Vite + Recharts
                    │    :3000     │
                    └──────────────┘
```

## Quick Start

### Prerequisites

- CMake 3.20+
- GCC 12+ or Clang 15+ (C++20 support)
- PostgreSQL 14+
- Node.js 18+
- OpenSSL dev headers (`libssl-dev`)
- libpq dev headers (`libpq-dev`)

### Build

```bash
# Create the database
sudo -u postgres createdb outpost

# Build the backend
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
cd ..

# Install frontend dependencies
cd frontend && npm install && cd ..
```

### Run

```bash
# Start the backend (from project root)
./build/outpost

# Start the frontend dev server (separate terminal)
cd frontend && npm run dev
```

Open `http://localhost:3000` in your browser. Default credentials: `admin` / `outpost`.

## Configuration

All config lives in `config/outpost.yaml`:

```yaml
syslog:
  udp_port: 5514
  tcp_port: 5514

postgres:
  host: localhost
  port: 5432
  dbname: outpost
  batch_size: 1000
  flush_interval_ms: 1000

api:
  port: 8080

auth:
  default_admin_user: "admin"
  default_admin_pass: "outpost"
  session_ttl_hours: 24

workers:
  parser_threads: 2

logging:
  level: info
```

Cloud integrations (M365, Azure) are configured via the Settings page in the UI or directly in the YAML under `integrations:`.

## Detection Rules

Rules are defined in YAML under `config/rules/`. The engine supports three rule types:

**Threshold** — fire when N events match within a time window, grouped by a field:

```yaml
- id: WIN-BF-001
  name: Windows RDP Brute Force
  severity: high
  type: threshold
  filter:
    source_type: windows
    action: login_failure
  condition:
    threshold: 15
    window: 5m
    group_by: src_ip
```

**Sequence** — fire when events occur in order within a window:

```yaml
- id: WIN-SEQ-001
  name: Credential Abuse Chain
  severity: critical
  type: sequence
  filter:
    source_type: windows
  condition:
    window: 10m
    group_by: user
    steps:
      - label: Explicit credential use
        filter: { action: explicit_credential_login }
      - label: Account creation
        filter: { action: account_created }
```

**Value List** — fire when a field matches a known-bad value:

```yaml
- id: AZ-RG-DEL-001
  name: Resource Group Deletion
  severity: critical
  type: valuelist
  filter:
    source_type: azure
  condition:
    field: action
    values:
      - resourcegroups_delete
```

Custom rules created through the web UI are stored in PostgreSQL and evaluated identically to YAML rules.

## Project Structure

```
src/
  api/           REST API server (cpp-httplib)
  auth/          Session auth, password hashing (OpenSSL SHA-256)
  common/        Event struct, logger, utilities
  ingestion/     Syslog listener, HTTP poller, ring buffer
  parser/        FortiGate, Windows, M365, Azure, Syslog parsers
  rules/         Rule engine, rule definitions, YAML loader
  storage/       PostgreSQL storage engine, retention
frontend/
  src/pages/     Dashboard, Events, Alerts, Reports, Rules, Connectors, Settings
  src/widgets/   Widget system for custom dashboards
config/
  outpost.yaml   Main configuration
  rules/         Detection rule YAML files
tests/           Google Test suite
```

## API

All endpoints are under `/api/` and require a bearer token (except login).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate, returns session token |
| GET | `/api/health` | System health and buffer stats |
| GET | `/api/events` | Query events with filters |
| GET | `/api/alerts` | List alerts |
| GET | `/api/rules` | List all rules (builtin + custom) |
| POST | `/api/rules` | Create custom detection rule |
| GET | `/api/reports/summary` | Full reporting data (KPIs, distributions, timelines) |
| GET | `/api/stats/timeline` | Event volume over time |
| GET | `/api/stats/sources` | Event count by source type |
| GET | `/api/users` | List users (admin only) |
| POST | `/api/connectors` | Create data connector |

## Dependencies

All C++ dependencies are fetched automatically via CMake FetchContent:

- [nlohmann/json](https://github.com/nlohmann/json) — JSON parsing
- [spdlog](https://github.com/gabime/spdlog) — Structured logging
- [yaml-cpp](https://github.com/jbeder/yaml-cpp) — YAML config and rule parsing
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — HTTP server and client
- [Google Test](https://github.com/google/googletest) — Unit testing

System: OpenSSL, libpq (PostgreSQL).

## Tests

```bash
cd build && ctest --output-on-failure
```

## License

MIT
