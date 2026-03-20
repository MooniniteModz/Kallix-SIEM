# Testing the PostgreSQL-Backed SIEM

## Step 1: Set Up PostgreSQL (One-time setup)

The PostgreSQL authentication requires some setup. Here's what you need to do:

### Option A: Use password authentication (Recommended for testing)

1. Set a password for the postgres user:
   ```bash
   sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'postgres';"
   ```

2. Create the databases:
   ```bash
   PGPASSWORD=postgres createdb -U postgres outpost
   PGPASSWORD=postgres createdb -U postgres outpost_test
   ```

3. Verify the databases exist:
   ```bash
   PGPASSWORD=postgres psql -U postgres -l
   ```

### Option B: Use peer authentication (without password)

The system uses peer authentication by default. This requires running commands as the postgres system user:

```bash
# This requires sudo without password prompt, or you can ask your admin to run it
sudo -u postgres createdb outpost
sudo -u postgres createdb outpost_test
```

## Step 2: Run the Outpost SIEM

```bash
# If you set a password in Step 1, Option A:
PGPASSWORD=postgres ./build/outpost

# Or if using peer auth (Option B), run as postgres user:
sudo -u postgres ./build/outpost
```

You should see output like:
```
[info] ║         OUTPOST SIEM v0.1.0               ║
[info] Outpost is running.
[info]   Syslog UDP/TCP: port 5514
[info]   REST API:       http://0.0.0.0:8080/api/health
[info]   PostgreSQL:     localhost:5432/outpost
```

## Step 3: Test with Syslog Events

In a separate terminal, send a syslog message:

```bash
# Send a test syslog event to the SIEM
echo "Test event from syslog" | nc -u -w0 127.0.0.1 5514
```

Or using logger (standard Linux syslog tool):
```bash
logger -h 127.0.0.1 -P 5514 "Test authentication event: user=admin action=login"
```

## Step 4: Test with API Calls

### Check health:
```bash
curl http://localhost:8080/api/health
```

### Query stored events:
```bash
# Get events from the last hour
curl "http://localhost:8080/api/events?hours=1"

# Search for events with keyword
curl "http://localhost:8080/api/events?hours=1&keyword=test"
```

### Get stats:
```bash
curl http://localhost:8080/api/stats
```

## Step 5: Verify in PostgreSQL

In another terminal, query the database directly:

```bash
# If using password auth:
PGPASSWORD=postgres psql -U postgres -d outpost -c "SELECT count(*) FROM events;"

# Or peer auth:
sudo -u postgres psql -d outpost -c "SELECT count(*) FROM events;"
```

### Useful queries:

```sql
-- See all events
SELECT event_id, timestamp, source_type, action, raw FROM events LIMIT 10;

-- Count events by source type
SELECT source_type, COUNT(*) FROM events GROUP BY source_type;

-- Search for specific events
SELECT * FROM events WHERE raw ILIKE '%login%' LIMIT 5;

-- See alerts
SELECT * FROM alerts;
```

## Step 6: Full Integration Test

1. **Terminal 1 - Run Outpost:**
   ```bash
   PGPASSWORD=postgres ./build/outpost
   ```

2. **Terminal 2 - Send events:**
   ```bash
   # Send multiple test events
   for i in {1..5}; do
     echo "Test event $i" | nc -u -w0 127.0.0.1 5514
     sleep 0.5
   done
   ```

3. **Terminal 3 - Query API:**
   ```bash
   # Wait a second for events to be flushed
   sleep 1

   # Get recent events
   curl "http://localhost:8080/api/events?hours=1" | jq .
   ```

4. **Terminal 3 - Query Database:**
   ```bash
   PGPASSWORD=postgres psql -U postgres -d outpost -c "SELECT COUNT(*) as total_events FROM events;"
   ```

## Architecture Diagram

```
Your Syslog/App            Outpost SIEM                    PostgreSQL
      │                         │                             │
      ├─→ (UDP:5514)   ──→ Parser Workers                    │
      │                    ├─ Ring Buffer                    │
      │                    ├─ Event Parsers                  │
      │                    ├─ Rule Engine                    │
      │                    └─ Flush Worker  ───→ TCP:5432 ──→ Database
      │                                                        │
      └─→ (REST:8080) ──→ API Server ─────→ Storage Engine ──→ Database
                           ├─ /api/health
                           ├─ /api/events
                           └─ /api/stats
```

## Troubleshooting

### "connection failed: FATAL: Peer authentication failed"
- You need to set a password (Option A) or use sudo to create the databases

### "connection to server at "localhost" (127.0.0.1), port 5432 failed"
- PostgreSQL may not be running: `sudo service postgresql status`
- Start it: `sudo service postgresql start`

### Events not appearing
- Check if Outpost is running (`ps aux | grep outpost`)
- Check firewall: `sudo ufw status` (allow 5514/udp)
- Verify events are being received: check Outpost logs for parse errors

### No events in database
- Ensure the flush thread is running (should see logs)
- Try querying with: `SELECT COUNT(*) FROM events;`
- Check alerts table: `SELECT * FROM alerts;`

## Learning Points

This test demonstrates:
✅ **C++ Integration** - PostgreSQL C client (libpq) integration
✅ **Network I/O** - Syslog UDP reception, API REST calls
✅ **Threading** - Parser workers and flush thread coordination
✅ **Transactions** - ACID guarantees for event storage
✅ **Error Handling** - Graceful degradation on connection failures
✅ **Security** - Parameterized queries, environment variables
