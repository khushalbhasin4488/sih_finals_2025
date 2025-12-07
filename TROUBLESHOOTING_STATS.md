# Troubleshooting: No Stats Showing

## Your Current Status

✅ **API is running** - `auto_analysis: true`  
✅ **3810 logs** in database  
✅ **474 alerts** generated (signature detection working)  
❌ **0 anomaly alerts** - Anomaly detection not triggering  
❌ **Stats may not show** if frontend can't connect or data is stale

## Problem Identified

The analysis service only processes **NEW logs** (logs created after the backend started). 

**What happened:**
1. You ran seeder → Created 3810 logs
2. You started backend → Backend only looks for NEW logs since startup
3. All 3810 logs are "old" → Not processed by analysis

## Solutions

### Solution 1: Force Analysis of All Logs (Recommended)

Create a script to manually trigger analysis of all existing logs:

```python
# File: backend/scripts/analyze_all_logs.py
import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db_manager import DuckDBManager
from analyzers.orchestrator import AnalysisOrchestrator

async def analyze_all_logs():
    db_path = "../data/duckdb/logs.db"
    db_manager = DuckDBManager(db_path)
    
    config = {
        'analysis_interval': 60,
        'batch_size': 10000,
        'signature_dir': '../config/signatures',
        'blocked_ips_file': '../config/blocked_ips.txt',
        'baseline_file': '../data/baselines.json',
        'update_baselines_on_start': False
    }
    
    orchestrator = AnalysisOrchestrator(db_manager, config)
    
    # Temporarily set last_processed_timestamp to None to process all logs
    orchestrator.last_processed_timestamp = None
    
    print("Analyzing all existing logs...")
    stats = await orchestrator.run_analysis_cycle()
    
    print(f"✓ Processed {stats['logs_processed']} logs")
    print(f"✓ Generated {stats['alerts_generated']} alerts")
    
    return stats

if __name__ == "__main__":
    asyncio.run(analyze_all_logs())
```

**Run it:**
```bash
cd backend
source .venv/bin/activate
python3 scripts/analyze_all_logs.py
```

### Solution 2: Restart Backend After Seeder

**Correct order:**
1. Start backend first (it will wait for logs)
2. Run seeder (creates new logs)
3. Backend automatically analyzes new logs every 60 seconds

**To fix now:**
1. Stop backend (Ctrl+C)
2. Restart backend
3. Run seeder again (even just 10-20 logs)
4. Backend will process the new logs

### Solution 3: Check Frontend Connection

Stats might be generated but frontend not showing them:

```bash
# Check if frontend can reach API
curl http://localhost:8000/api/v1/stats

# Check if frontend is running
curl http://localhost:3000
```

**Frontend should be running:**
```bash
cd frontend
npm run dev
```

## Why Anomaly Detection Shows 0

Anomaly detection needs:
1. **Baselines** - Only `requests_per_ip` exists, need more
2. **Pattern matching** - Logs need to match anomaly patterns
3. **Statistical deviation** - Values need to exceed thresholds

**Check baselines:**
```bash
cat data/baselines.json
```

**Should have baselines for:**
- login_frequency
- failed_login_rate  
- requests_per_ip ✓ (you have this)
- error_rate
- command_execution_rate

**Fix:** The baselines will be created automatically, but you may need more diverse logs or wait for baseline updates.

## Quick Diagnostic Commands

```bash
# 1. Check API status
curl http://localhost:8000/ | jq

# 2. Check total logs
curl http://localhost:8000/api/v1/health | jq '.total_logs'

# 3. Check alerts
curl "http://localhost:8000/api/v1/alerts?limit=5" | jq

# 4. Check stats
curl http://localhost:8000/api/v1/stats | jq

# 5. Check anomaly stats
curl "http://localhost:8000/api/v1/alerts/stats" | jq '.anomaly_detection'
```

## Expected Behavior

After running the analyze_all_logs script:
- ✅ All 3810 logs processed
- ✅ More alerts generated (signature + anomaly)
- ✅ Stats populated in dashboard
- ✅ Anomaly detection working (if patterns match)

## Next Steps

1. **Run the analyze_all_logs script** (Solution 1)
2. **Check frontend** - Make sure it's running on port 3000
3. **View dashboard** - http://localhost:3000/dashboard
4. **Check reports** - http://localhost:3000/reports

The stats ARE being generated (474 alerts prove it), you just need to either:
- Process the existing logs (Solution 1)
- Or generate new logs after backend starts (Solution 2)

