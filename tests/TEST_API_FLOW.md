# Testing API Flow: Syslog to PostgreSQL

## 📊 Complete Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        YOUR APPLICATION/SYSTEM                            │
│  (Sends syslog messages, API calls, logs, etc.)                          │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
         ┌──────────▼──────┐  ┌───────▼─────────┐
         │  Syslog (UDP)   │  │  REST API       │
         │  Port 5514      │  │  Port 8080      │
         └──────────┬──────┘  └───────┬─────────┘
                    │                 │
                    └────────┬────────┘
                             │
        ┌────────────────────▼────────────────────┐
        │   Outpost SIEM Application              │
        │   (C++ with PostgreSQL backend)         │
        ├─────────────────────────────────────────┤
        │                                          │
        │  ┌────────────────────────────────────┐ │
        │  │ Ingestion Layer                    │ │
        │  │ - SyslogListener (UDP receiver)    │ │
        │  │ - RingBuffer (65536 slot buffer)   │ │
        │  │ - HttpPoller (API client)          │ │
        │  └────────────────────────────────────┘ │
        │                    │                      │
        │                    ▼                      │
        │  ┌────────────────────────────────────┐ │
        │  │ Parser Layer (2 worker threads)    │ │
        │  │ - FortiGateParser                  │ │
        │  │ - WindowsParser                    │ │
        │  │ - M365Parser                       │ │
        │  │ - AzureParser                      │ │
        │  │ - SyslogParser                     │ │
        │  └────────────────────────────────────┘ │
        │                    │                      │
        │  ┌─────────────────┴──────────────────┐ │
        │  │                                    │  │
        │  ▼                                    ▼  │
        │ ┌──────────────────┐  ┌────────────────┐│
        │ │ RuleEngine       │  │ StorageEngine  ││
        │ │ (Event detection)│  │ (Buffering)    ││
        │ └──────────────────┘  └────────────────┘│
        │                             │             │
        │                   ┌─────────▼─────────┐ │
        │                   │ Write Buffer      │ │
        │                   │ (1000 events max) │ │
        │                   └─────────┬─────────┘ │
        │                             │             │
        │  ┌──────────────────────────▼────────┐  │
        │  │ Flush Worker Thread (every 1 sec) │  │
        │  │ - Executes batched INSERT         │  │
        │  │ - Uses PostgreSQL transactions    │  │
        │  └──────────────────────────┬────────┘  │
        │                             │            │
        └─────────────────────────────┼────────────┘
                                      │
                          ┌───────────▼────────────┐
                          │  PostgreSQL Database   │
                          │  localhost:5432        │
                          ├────────────────────────┤
                          │ Tables:                │
                          │ - events (event log)   │
                          │ - alerts (detections)  │
                          │ - indexes (FTS, etc)   │
                          └────────────────────────┘
```

## 🚀 Quick Start Testing

### 1. Set Up PostgreSQL
```bash
# Run the setup script
bash /tmp/setup_postgres.sh
```

### 2. Start the SIEM in Terminal 1
```bash
export PGPASSWORD=postgres
/home/moon/UPT-Outpost/build/outpost
```

**Expected output:**
```
[info] ║         OUTPOST SIEM v0.1.0               ║
[info] Outpost is running.
[info]   Syslog UDP/TCP: port 5514
[info]   REST API:       http://0.0.0.0:8080/api/health
[info]   PostgreSQL:     localhost:5432/outpost
[info]   Detection rules: 0 (load rules with yaml files in ./config/rules)
```

### 3. Send Test Events in Terminal 2

#### Option A: Simple Syslog Event
```bash
echo "Test login event from server" | nc -u -w0 127.0.0.1 5514
```

#### Option B: Multiple Events (Loop)
```bash
for i in {1..5}; do
    echo "User admin performed action $i" | nc -u -w0 127.0.0.1 5514
    sleep 0.1
done
```

#### Option C: Use logger Command (Standard Linux)
```bash
logger -h 127.0.0.1 -P 5514 -t outpost-test "Authentication successful"
```

### 4. Query via REST API in Terminal 3

```bash
# Check health
curl http://localhost:8080/api/health

# Get recent events
curl "http://localhost:8080/api/events?hours=1" | jq .

# Search for events with keyword
curl "http://localhost:8080/api/events?hours=1&keyword=login" | jq .
```

### 5. Verify in PostgreSQL in Terminal 4

```bash
export PGPASSWORD=postgres

# Count total events
psql -U postgres -d outpost -c "SELECT COUNT(*) as total_events FROM events;"

# View recent events
psql -U postgres -d outpost -c "SELECT event_id, timestamp, action, raw FROM events ORDER BY timestamp DESC LIMIT 5;"

# See events by source type
psql -U postgres -d outpost -c "SELECT source_type, COUNT(*) FROM events GROUP BY source_type;"

# Full event details
psql -U postgres -d outpost -c "\x" -c "SELECT * FROM events LIMIT 1;"
```

## 🔍 Understanding the C++ Flow

### What Happens Behind the Scenes:

1. **Event Reception** (SyslogListener.cpp)
   ```cpp
   // Receives UDP packet on port 5514
   udp_socket.recvfrom(buffer, addr)  // Async, non-blocking
   ```

2. **Buffering** (RingBuffer.h)
   ```cpp
   // Lockfree ring buffer - parser workers pop from here
   write_buffer_.push(message)  // O(1), thread-safe
   ```

3. **Parsing** (parser_worker thread in main.cpp)
   ```cpp
   // Each parser tries to match the event format
   for (auto& parser : parsers) {
       if (auto event = parser->parse(*msg)) {
           storage.insert(*event);  // Add to write buffer
           break;
       }
   }
   ```

4. **Buffering in Storage** (PostgresStorageEngine::insert)
   ```cpp
   {
       std::lock_guard<std::mutex> lock(write_mutex_);  // Thread-safe
       write_buffer_.push_back(event);  // Memory buffer, not DB
   }
   ```

5. **Periodic Flush** (flush_worker thread)
   ```cpp
   // Every 1 second (configurable):
   storage.flush();  // Batches all buffered events into DB transaction
   ```

6. **Database Write** (PostgresStorageEngine::flush)
   ```cpp
   PQexec(conn_, "BEGIN;");  // Start transaction

   for (const auto& e : write_buffer_) {
       PQexecParams(conn_, INSERT_SQL, params...);  // Parameterized query
   }

   PQexec(conn_, "COMMIT;");  // Atomic: all or nothing
   ```

## 📈 Performance Characteristics

### What You'll Observe:

| Metric | Value |
|--------|-------|
| **Max Buffer** | 1000 events |
| **Flush Interval** | 1 second |
| **Max Latency** | ~1 second (event in DB) |
| **Throughput** | ~1000 events/sec (1 batch/sec) |
| **Transaction Safety** | ACID (all-or-nothing) |

### Example Timeline:

```
T=0s   → Send 100 events via syslog
T=0.5s → Events in write_buffer_, not yet in DB
T=1s   → flush_worker wakes up, writes 100 events in 1 transaction
T=1.1s → Events visible in PostgreSQL, API queries return them
```

## 🧪 Detailed Test Scenario

### Scenario: Detecting Failed Login Attempts

```bash
# Terminal 1: Start SIEM
export PGPASSWORD=postgres
/home/moon/UPT-Outpost/build/outpost

# Terminal 2: Simulate failed logins
for attempt in {1..3}; do
    echo "Failed login for user admin from 10.0.0.50" | \
        nc -u -w0 127.0.0.1 5514
    sleep 0.2
done

# Terminal 3: Query via API while events are being processed
sleep 1  # Wait for flush
curl "http://localhost:8080/api/events?hours=1&keyword=login" | jq '.events[].action'

# Terminal 4: Query database directly
export PGPASSWORD=postgres
psql -U postgres -d outpost << EOF
SELECT timestamp, action, raw
FROM events
WHERE raw ILIKE '%login%'
ORDER BY timestamp DESC;
EOF
```

## 📝 What to Check

### ✅ Verification Checklist:

- [ ] Outpost starts without connection errors
- [ ] Syslog messages are received (check logs for parse messages)
- [ ] No "Failed to insert event" errors in logs
- [ ] API `/api/health` returns success
- [ ] API `/api/events` returns JSON with event list
- [ ] PostgreSQL query shows event count > 0
- [ ] Event timestamps match when you sent them
- [ ] Event content matches what you sent

### ❌ Troubleshooting:

```bash
# 1. Is PostgreSQL running?
ps aux | grep postgres | grep -v grep

# 2. Can you connect to PostgreSQL?
export PGPASSWORD=postgres
psql -U postgres -c "SELECT version();"

# 3. Do the databases exist?
export PGPASSWORD=postgres
psql -U postgres -l | grep outpost

# 4. Are there events in the database?
export PGPASSWORD=postgres
psql -U postgres -d outpost -c "SELECT COUNT(*) FROM events;"

# 5. Check Outpost logs for errors
# Look for [error] or [critical] lines in output
```

## 🎓 What This Demonstrates

Your new PostgreSQL SIEM demonstrates:

✅ **C++ Knowledge:**
- Object-oriented design (classes, inheritance)
- Thread safety (mutexes, lock guards)
- Memory management (pointers, destructors)
- Library integration (libpq C API)

✅ **Database Design:**
- Schema with indexes
- Transactions for ACID properties
- Parameterized queries for security
- Full-text search (tsvector)

✅ **System Design:**
- Event streaming architecture
- Producer-consumer pattern (ring buffer)
- Batching for performance
- REST API for queries

✅ **Networking:**
- UDP syslog reception
- TCP PostgreSQL connection
- HTTP/REST server
- Event parsing and normalization

## 🔬 Advanced Testing

### Load Testing (Generate 1000 events):
```bash
# Terminal 2
for i in {1..1000}; do
    echo "Event $i from source" | nc -u -w0 127.0.0.1 5514 &
done
wait

# Terminal 4: Check if all arrived
sleep 2
export PGPASSWORD=postgres
psql -U postgres -d outpost -c "SELECT COUNT(*) FROM events;"
```

### Concurrent API Requests:
```bash
# Terminal 3
for i in {1..100}; do
    curl -s "http://localhost:8080/api/events?hours=1" > /dev/null &
done
wait
echo "100 concurrent requests completed"
```

## 📚 References

- PostgreSQL docs: https://www.postgresql.org/docs/16/
- libpq (C API): https://www.postgresql.org/docs/16/libpq.html
- Syslog format: RFC 3164 / RFC 5424
- Your code: `/home/moon/UPT-Outpost/src/storage/postgres_storage_engine.cpp`
