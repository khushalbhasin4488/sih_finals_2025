# Automatic Analysis System - User Guide

## Overview
The log analyzer now runs **completely automatically** - no manual baseline creation or orchestrator running needed!

## What Happens Automatically

### On API Startup
1. ✅ **Checks for baselines** - If missing, creates them from existing logs
2. ✅ **Starts orchestrator** - Analyzes logs every 60 seconds
3. ✅ **Starts baseline scheduler** - Updates baselines every 24 hours

### Continuous Operation
- **Every 60 seconds**: Orchestrator analyzes new logs and generates alerts
- **Every 24 hours**: Baselines update with last 7 days of data
- **Always**: System monitors for threats automatically

## Usage

### Start the API (That's It!)
```bash
cd backend
source .venv/bin/activate
python3 -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

**What you'll see:**
```
INFO: Starting up API...
INFO: No baselines found, creating initial baselines...
INFO: Creating baselines from 1500 existing logs
INFO: Initial baselines created successfully
INFO: Orchestrator initialized
INFO: Analysis service started (runs every 60 seconds)
INFO: Baseline scheduler started (updates every 24 hours)
INFO: API startup complete - automatic analysis is running
```

### View Alerts in Frontend
Just open: **http://localhost:3000/alerts**

Alerts appear automatically as the orchestrator detects threats!

## System Status

### Check if Services are Running
```bash
curl http://localhost:8000/ | jq
```

Response:
```json
{
  "message": "Log Analyzer API",
  "version": "1.0.0",
  "status": "running",
  "auto_analysis": true,
  "baseline_scheduler": true
}
```

### View Recent Alerts
```bash
curl "http://localhost:8000/api/v1/alerts?limit=10" | jq
```

## How It Works

### First Startup (No Baselines)
```
API Starts
    ↓
Check: baselines.json exists?
    ↓ NO
Count logs in database
    ↓
> 100 logs? → Create baselines from last 7 days
< 100 logs? → Create baselines from available data
    ↓
Start Orchestrator (every 60s)
    ↓
Start Baseline Scheduler (every 24h)
    ↓
System Running Automatically!
```

### Subsequent Startups (Baselines Exist)
```
API Starts
    ↓
Check: baselines.json exists?
    ↓ YES
Load existing baselines
    ↓
Start Orchestrator (every 60s)
    ↓
Start Baseline Scheduler (every 24h)
    ↓
System Running Automatically!
```

### Continuous Operation
```
┌─────────────────────────────────────┐
│  Every 60 seconds:                  │
│  1. Fetch new logs                  │
│  2. Run signature detector          │
│  3. Run anomaly detector            │
│  4. Store alerts                    │
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│  Every 24 hours:                    │
│  1. Fetch last 7 days of logs       │
│  2. Calculate new baselines         │
│  3. Update baselines.json           │
└─────────────────────────────────────┘
```

## Files Created

### Services
- `backend/services/analysis_service.py` - Continuous orchestrator runner
- `backend/services/baseline_scheduler.py` - Automatic baseline updater
- `backend/services/__init__.py` - Package init

### Data
- `data/baselines.json` - Auto-created on first run

### Modified
- `backend/api/main.py` - Added startup/shutdown handlers

## Configuration

All settings are in the code (can be moved to config file later):

```python
# Orchestrator runs every 60 seconds
analysis_service = AnalysisService(orchestrator, interval=60)

# Baselines update every 24 hours using last 7 days
baseline_scheduler = BaselineScheduler(
    baseline_manager,
    update_interval=86400,  # 24 hours
    historical_days=7
)
```

## Troubleshooting

### No alerts appearing?
- Wait 60 seconds for first analysis cycle
- Check API logs for errors
- Verify seeder is generating logs

### Baselines not created?
- Check if database has logs (`curl http://localhost:8000/api/v1/health`)
- Look for startup errors in API logs
- Manually check `data/baselines.json` exists

### Services not running?
```bash
# Check service status
curl http://localhost:8000/ | jq '.auto_analysis, .baseline_scheduler'

# Should return: true, true
```

### Stop the system
```bash
# Just stop the API (Ctrl+C)
# Services will shutdown gracefully
```

## Benefits

✅ **Zero Manual Work** - Everything automatic
✅ **Always Monitoring** - 24/7 threat detection
✅ **Self-Adapting** - Baselines update daily
✅ **Production Ready** - Graceful shutdown, error handling
✅ **Easy to Use** - Just start the API!

## What You DON'T Need to Do Anymore

❌ ~~Manually create baselines~~
❌ ~~Run orchestrator script~~
❌ ~~Schedule baseline updates~~
❌ ~~Monitor for new logs~~

Everything happens automatically! 🎉
