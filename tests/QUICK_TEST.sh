#!/bin/bash
# Quick Test Script - Run this to test Outpost SIEM with PostgreSQL
# Usage: bash QUICK_TEST.sh

set -e

echo "🚀 Outpost SIEM + PostgreSQL Quick Test"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Setup
echo -e "${BLUE}[1/4] Setting up PostgreSQL...${NC}"
export PGPASSWORD=postgres

# Create databases
createdb -U postgres outpost 2>/dev/null || echo "  → outpost database exists"
createdb -U postgres outpost_test 2>/dev/null || echo "  → outpost_test database exists"
echo -e "${GREEN}✓ Databases ready${NC}"
echo ""

# Step 2: Start SIEM
echo -e "${BLUE}[2/4] Starting Outpost SIEM...${NC}"
# Run in background
/home/moon/UPT-Outpost/build/outpost > /tmp/outpost.log 2>&1 &
SIEM_PID=$!
echo "  → PID: $SIEM_PID"
sleep 2  # Wait for startup
echo -e "${GREEN}✓ Outpost running${NC}"
echo ""

# Step 3: Send test events
echo -e "${BLUE}[3/4] Sending test events...${NC}"
for i in {1..5}; do
    echo "Test event number $i from test system" | nc -u -w0 127.0.0.1 5514
    sleep 0.1
done
echo -e "${GREEN}✓ Sent 5 test events${NC}"
echo ""

# Wait for flush
sleep 1.5

# Step 4: Verify
echo -e "${BLUE}[4/4] Verifying in PostgreSQL...${NC}"
RESULT=$(psql -U postgres -d outpost -t -c "SELECT COUNT(*) FROM events;")
echo "  → Events in database: $RESULT"

if [ "$RESULT" -gt 0 ]; then
    echo -e "${GREEN}✓ SUCCESS! Events stored in PostgreSQL${NC}"
    echo ""
    echo "📊 Events received:"
    psql -U postgres -d outpost -c "SELECT event_id, source_type, action, raw FROM events ORDER BY timestamp DESC LIMIT 5;"
else
    echo -e "${YELLOW}⚠ No events found${NC}"
    echo "Check /tmp/outpost.log for errors:"
    tail /tmp/outpost.log
fi

echo ""
echo "🧹 Cleanup:"
echo "  Kill SIEM: kill $SIEM_PID"
echo "  Or use:   pkill -f 'build/outpost'"
echo ""
echo "📖 For more tests, see TEST_API_FLOW.md"
