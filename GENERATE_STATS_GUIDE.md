# How to Generate Stats - Quick Start Guide

## Overview
To generate stats, you need:
1. **Logs in the database** (use the seeder)
2. **API running** (automatically analyzes logs every 60 seconds)
3. **Baselines created** (happens automatically if you have >100 logs)

## Step-by-Step Instructions

### Step 1: Generate Logs (Required First)

The database needs logs before stats can be generated. Use the seeder:

```bash
# From project root directory
python3 temp_seeder/seeder.py 50 2
```

This generates:
- **50 logs** every **2 seconds**
- Mix of normal traffic, signature attacks, and anomaly bursts
- Continue for 5-10 minutes to build enough data

**Recommended**: Run for at least 5 minutes to build baselines:
```bash
# Generate 20 logs every 3 seconds for 5 minutes
python3 temp_seeder/seeder.py 20 3
# Let it run for 5-10 minutes, then press Ctrl+C
```

### Step 2: Start the Backend API

The API automatically:
- Creates baselines (if >100 logs exist)
- Starts analysis every 60 seconds
- Generates alerts from logs

```bash
cd backend
source .venv/bin/activate  # or: python3 -m venv .venv && source .venv/bin/activate
python3 -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

**What you'll see:**
```
INFO: Starting up API...
INFO: No baselines found, creating initial baselines...
INFO: Creating baselines from 500 existing logs
INFO: Initial baselines created successfully
INFO: Orchestrator initialized
INFO: Analysis service started (runs every 60 seconds)
INFO: Baseline scheduler started (updates every 24 hours)
INFO: API startup complete - automatic analysis is running
```

### Step 3: Wait for Analysis Cycles

The orchestrator runs **every 60 seconds** automatically. After the first cycle completes, you'll have:
- ✅ Alerts in the database
- ✅ Stats available via API
- ✅ Dashboard showing data

**Check if analysis is working:**
```bash
# Check service status
curl http://localhost:8000/ | jq

# Should show:
# {
#   "auto_analysis": true,
#   "baseline_scheduler": true
# }
```

### Step 4: View Stats

#### Option A: Frontend Dashboard
Open: **http://localhost:3000/dashboard**

#### Option B: Frontend Reports
Open: **http://localhost:3000/reports**

#### Option C: API Endpoints
```bash
# Get dashboard stats
curl http://localhost:8000/api/v1/stats | jq

# Get alert stats (includes anomaly detection)
curl http://localhost:8000/api/v1/alerts/stats | jq

# Get alerts
curl http://localhost:8000/api/v1/alerts?limit=10 | jq

# Get anomaly trend
curl http://localhost:8000/api/v1/anomalies/trend?hours=24 | jq
```

## Quick Test Script

Run this to quickly generate stats:

```bash
#!/bin/bash
# Quick stats generation script

echo "Step 1: Starting seeder (will run for 2 minutes)..."
python3 temp_seeder/seeder.py 30 2 &
SEEDER_PID=$!

# Wait 2 minutes
sleep 120

# Stop seeder
kill $SEEDER_PID 2>/dev/null
echo "Seeder stopped. You should have ~1800 logs now."

echo ""
echo "Step 2: Starting API..."
echo "In another terminal, run:"
echo "  cd backend && source .venv/bin/activate && python3 -m uvicorn api.main:app --reload"
echo ""
echo "Step 3: Wait 60 seconds for first analysis cycle"
echo "Step 4: Visit http://localhost:3000/dashboard"
```

## Troubleshooting

### No Stats Showing?

1. **Check if logs exist:**
   ```bash
   curl http://localhost:8000/api/v1/health | jq
   # Should show total_logs > 0
   ```

2. **Check if baselines exist:**
   ```bash
   ls -la data/baselines.json
   # Should exist if you have >100 logs
   ```

3. **Check if analysis is running:**
   ```bash
   curl http://localhost:8000/ | jq '.auto_analysis'
   # Should return: true
   ```

4. **Check API logs** for errors:
   - Look for "Analysis cycle completed" messages
   - Check for any error messages

### No Anomaly Stats?

Anomaly detection needs baselines. If you have <100 logs:
- Baselines may not be accurate
- Anomaly detection may not work well
- **Solution**: Generate more logs (run seeder longer)

### No Alerts Generated?

1. **Wait 60 seconds** - Analysis runs every minute
2. **Check logs** - Make sure seeder is generating logs
3. **Check signatures** - Verify `config/signatures/` files exist
4. **Check database** - Ensure logs are being stored

## Expected Results

After running seeder for 5-10 minutes and waiting for analysis:

- **Total Logs**: 1000-5000+ logs
- **Alerts**: 50-200+ alerts (signature + anomaly)
- **Anomaly Alerts**: 10-50+ anomaly detections
- **Stats**: All dashboard metrics populated

## Manual Analysis (Optional)

If you want to trigger analysis immediately without waiting:

```python
# In Python shell or script
import asyncio
from backend.storage.db_manager import DuckDBManager
from backend.analyzers.orchestrator import AnalysisOrchestrator

db_manager = DuckDBManager('data/duckdb/logs.db')
config = {
    'analysis_interval': 60,
    'batch_size': 10000,
    'signature_dir': 'config/signatures',
    'blocked_ips_file': 'config/blocked_ips.txt',
    'baseline_file': 'data/baselines.json',
    'update_baselines_on_start': False
}

orchestrator = AnalysisOrchestrator(db_manager, config)
stats = asyncio.run(orchestrator.run_analysis_cycle())
print(f"Processed {stats['logs_processed']} logs, generated {stats['alerts_generated']} alerts")
```

## Summary

**Minimum to get stats:**
1. Run seeder: `python3 temp_seeder/seeder.py 20 3` (for 5+ minutes)
2. Start API: `cd backend && python3 -m uvicorn api.main:app --reload`
3. Wait 60 seconds for first analysis cycle
4. View stats at http://localhost:3000/dashboard

That's it! The system handles everything else automatically.

