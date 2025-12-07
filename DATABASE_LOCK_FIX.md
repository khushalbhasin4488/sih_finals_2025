# Database Lock Issue - Quick Fix

## Problem
DuckDB doesn't allow multiple write connections. When the API (with automatic orchestrator) is running, the seeder can't write to the database.

## Solutions

### Option 1: Stop Seeder When API is Running (Recommended)
The automatic orchestrator is now analyzing logs continuously, so you don't need the seeder running at the same time.

**Workflow:**
1. Run seeder to generate initial logs
2. Stop seeder (Ctrl+C)
3. Start API (automatic analysis begins)
4. View alerts in frontend

```bash
# Step 1: Generate logs
python3 temp_seeder/seeder.py 100 1
# Wait 2-3 minutes, then Ctrl+C

# Step 2: Start API (automatic analysis)
cd backend && source .venv/bin/activate
python3 -m uvicorn api.main:app --reload

# Step 3: View alerts
# Open http://localhost:3000/alerts
```

### Option 2: Use API to Ingest Logs
Instead of seeder writing directly, send logs via API endpoint (future enhancement).

### Option 3: Temporary - Stop API, Run Seeder, Restart API
```bash
# Stop API (Ctrl+C in API terminal)

# Run seeder
python3 temp_seeder/seeder.py 50 2
# Wait, then Ctrl+C

# Restart API
cd backend && python3 -m uvicorn api.main:app --reload
```

## Why This Happens

DuckDB uses file-based locking:
- API holds a write lock (for storing alerts)
- Seeder tries to get write lock (for storing logs)
- DuckDB rejects second write connection

## Current Seeder Improvements

The seeder now has retry logic:
- Retries 3 times with exponential backoff
- Waits 1s, 2s, 4s between attempts
- Better error messages

## Recommended Workflow

**For Development/Testing:**
```bash
# Terminal 1: Generate initial dataset
python3 temp_seeder/seeder.py 200 1
# Run for 5 minutes, then stop

# Terminal 2: Start API (auto-analysis)
cd backend && source .venv/bin/activate
python3 -m uvicorn api.main:app --reload

# Terminal 3: Start Frontend
cd frontend && npm run dev

# Browser: View alerts
http://localhost:3000/alerts
```

**For Production:**
- Use real log ingestion (syslog, filebeat, etc.)
- API analyzes logs automatically
- No seeder needed

## Future Enhancement

Create an API endpoint for log ingestion:
```python
@app.post("/api/v1/logs/ingest")
async def ingest_logs(logs: List[LogCreate]):
    # Store logs via API
    # No database lock conflict
```

This would allow the seeder to POST logs to the API instead of writing directly to the database.
