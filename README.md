## Outpost SIEM <img width="30" height="30" alt="image" src="https://github.com/user-attachments/assets/72e3ce98-0adb-43a9-a02f-6fb9916f86f3" />



A lightweight, self-hosted SIEM built in C++20 with a React frontend. This project aimed to provide a highly customized SIEM with no cost overhead besides compute.

Outpost ingests logs from syslog, cloud APIs (M365, Azure Monitor, Microsoft Graph), and network appliances (FortiGate, UniFi), normalizes them into a common event format, runs detection rules against the stream, and stores everything in PostgreSQL.

---

## Features

- **Multi-source ingestion** — Syslog (UDP/TCP), Microsoft 365 Management API, Azure Monitor Activity Log, Microsoft Graph sign-in logs, FortiGate, UniFi, Windows Event Logs, SentinelOne, and generic REST API connectors
- **Lock-free ring buffer** — Events flow through a wait-free MPSC buffer between ingestion and storage threads
- **Detection engine** — Threshold, sequence, and value-list rule types with sliding windows and per-group state tracking
- **30+ built-in rules** — Brute force, privilege escalation, log tampering, impossible travel, credential abuse chains, and more
- **Custom rule builder** — Create and edit rules from the web UI; stored in PostgreSQL and hot-loaded into the engine
- **PostgreSQL storage** — Batch inserts, full-text search via `tsvector`, configurable retention
- **REST API** — JSON API for events, alerts, stats, rules, connectors, integrations, and user management
- **Session auth** — SHA-256 password hashing via OpenSSL, bearer token sessions, role-based access (admin/analyst/viewer), email-based password reset via SMTP
- **React dashboard** — Clickable charts that drill down into filtered event views, customizable widget-based layout
- **3D Geospatial Globe** — Live login and event origin visualization mapped to real-world coordinates
- **Custom dashboard builder** — Drag-and-drop widget system for building personalized views
- **Reporting** — Executive overview, threat analysis, and operational KPI dashboards

## Architecture

```
                    ┌────────────────────┐
                    │    Syslog UDP/TCP  │
                    │    HTTP Poller     │ ← M365 / Azure OAuth2 / Graph API
                    │    REST Connectors │ ← FortiGate, UniFi, SentinelOne, custom
                    └────────┬───────────┘
                             │
                    ┌────────▼───────┐
                    │  Ring Buffer   │  lock-free, bounded MPSC
                    └────────┬───────┘
                             │
                ┌────────────▼──────────┐
                │    Parser Workers     │  FortiGate, Windows, M365, Azure,
                │    (N threads)        │  UniFi, SentinelOne, Syslog → Event
                └────────────┬──────────┘
                             │
              ┌──────────────▼────────────┐
              │       Rule Engine         │  threshold / sequence / valuelist
              │   (evaluate per event)    │
              └──────────────┬────────────┘
                             │
                    ┌────────▼───────┐
                    │  PostgreSQL    │  events, alerts, users, connectors,
                    │                │  custom rules, sessions, geo data
                    └────────┬───────┘
                             │
                    ┌────────▼───────┐
                    │   REST API     │  cpp-httplib — :8080
                    └────────┬───────┘
                             │
                    ┌────────▼───────┐
                    │    React       │  Vite + Recharts + Three.js
                    │    :3000       │  Dashboard, Globe, Builder, Reports
                    └────────────────┘
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

# Set up config (copy example and fill in your credentials)
cp config/outpost.yaml.example config/outpost.yaml

# Build the backend
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
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

Copy `config/outpost.yaml.example` to `config/outpost.yaml` and fill in your credentials. The actual `outpost.yaml` is gitignored to prevent secrets from being committed.

Cloud integrations (M365, Azure Monitor, Microsoft Graph sign-in logs) are configured via the Settings page in the UI or directly in the YAML under `integrations:`. Generic REST API connectors (FortiGate, UniFi, SentinelOne, etc.) are managed through the Data Sources page and stored in PostgreSQL.

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
  api/           REST API server and route handlers (cpp-httplib)
  auth/          Session auth, password hashing (OpenSSL SHA-256), SMTP password reset
  common/        Event struct, logger, utilities
  ingestion/     Syslog listener, HTTP poller (M365/Azure/Graph), REST connector manager, ring buffer
  parser/        FortiGate, Windows, M365, Azure, UniFi, SentinelOne, Syslog parsers
  rules/         Rule engine, rule definitions, YAML loader
  storage/       PostgreSQL storage engine, alerts, connectors, geo queries, retention
frontend/
  src/pages/     Dashboard, DashboardBuilder, Events, Alerts, Reports, Rules, DataSources, Settings
  src/components/ Globe3D, GeoMap, ActiveRules, RuleBuilder, EditRuleModal, WidgetModal
  src/widgets/   Widget renderer for custom dashboards
  src/utils/     Shared formatters and constants
config/
  outpost.yaml.example   Reference configuration (copy to outpost.yaml and fill in secrets)
  rules/                 Built-in detection rule YAML files
tests/           Google Test suite
```

## API

All endpoints are under `/api/` and require a bearer token (except login).

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate, returns session token |
| POST | `/api/auth/logout` | Invalidate session |
| GET | `/api/auth/me` | Current user info |
| POST | `/api/auth/forgot-password` | Send password reset email |
| POST | `/api/auth/reset-password` | Complete password reset |
| GET | `/api/health` | System health and buffer stats |
| GET | `/api/events` | Query events with time range, keyword, and source filters |
| GET | `/api/alerts` | List alerts |
| POST | `/api/alerts/acknowledge` | Acknowledge an alert |
| POST | `/api/alerts/close` | Close an alert |
| GET | `/api/rules` | List all rules (built-in + custom) |
| POST | `/api/rules` | Create custom detection rule |
| PUT | `/api/rules` | Update custom detection rule |
| DELETE | `/api/rules` | Delete custom detection rule |
| GET | `/api/stats` | Aggregate event counts and KPIs |
| GET | `/api/stats/timeline` | Event volume over time |
| GET | `/api/stats/sources` | Event count by source type |
| GET | `/api/stats/categories` | Event count by category |
| GET | `/api/stats/severity` | Event count by severity |
| GET | `/api/stats/top-ips` | Top source IPs |
| GET | `/api/stats/top-users` | Top users by event count |
| GET | `/api/stats/top-actions` | Top event actions |
| GET | `/api/reports/summary` | Full reporting data (KPIs, distributions, timelines) |
| GET | `/api/geo/points` | Geolocation points for globe visualization |
| GET | `/api/connectors` | List data source connectors |
| POST | `/api/connectors` | Create data source connector |
| PUT | `/api/connectors` | Update connector |
| DELETE | `/api/connectors` | Delete connector |
| POST | `/api/connectors/test` | Test connector credentials |
| GET | `/api/connectors/types` | List supported connector types |
| GET | `/api/integrations` | Get M365/Azure integration config |
| POST | `/api/integrations` | Update M365/Azure integration config |
| GET | `/api/users` | List users (admin only) |
| POST | `/api/users` | Create user |
| PUT | `/api/users` | Update user |
| DELETE | `/api/users` | Delete user |

## Dependencies

All C++ dependencies are fetched automatically via CMake FetchContent:

- [nlohmann/json](https://github.com/nlohmann/json) — JSON parsing
- [spdlog](https://github.com/gabime/spdlog) — Structured logging
- [yaml-cpp](https://github.com/jbeder/yaml-cpp) — YAML config and rule parsing
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — HTTP server and client (HTTPS via OpenSSL)
- [Google Test](https://github.com/google/googletest) — Unit testing

System: OpenSSL (`libssl-dev`), libpq (`libpq-dev`, PostgreSQL C client).

## Tests

```bash
cd build && ctest --output-on-failure
```

## License

MIT
