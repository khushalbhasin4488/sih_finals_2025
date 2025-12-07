# Log Analyzer - Complete Run Guide

This guide explains how to run the complete log analyzer system after starting the backend and frontend.

## Prerequisites

- Python 3.11+ installed
- Node.js 18+ and npm installed
- DuckDB database (created automatically)

## Quick Start

### 1. Start the Backend API

```bash
cd backend
python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

The API will:
- Initialize the database schema
- Create baselines for anomaly detection
- Start the analysis orchestrator (runs every 60 seconds)
- Start the baseline scheduler (updates daily)

**Expected output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
INFO:     Analysis orchestrator initialized
INFO:     Analysis service started (runs every 60 seconds)
```

### 2. Start the Frontend

In a new terminal:

```bash
cd frontend
npm install  # Only needed first time
npm run dev
```

The frontend will start on `http://localhost:3000`

**Expected output:**
```
  ▲ Next.js 14.x.x
  - Local:        http://localhost:3000
```

### 3. Seed Logs with All Detection Methods

In a new terminal, run the enhanced seeder:

```bash
cd temp_seeder
python seeder.py 10 1.0 10
```

**Parameters:**
- `10` - Batch size (logs per batch)
- `1.0` - Interval between batches (seconds)
- `10` - Duration in minutes

This will generate logs for **10 minutes** that trigger all 7 detection methods:
1. **Signature Detection** - SQL injection, XSS, path traversal
2. **Anomaly Detection** - Statistical anomalies (login spikes, failed attempts)
3. **Heuristic Analysis** - Brute force, privilege escalation, lateral movement, data exfiltration
4. **Behavioral Analysis** - Unusual login times, unusual IPs, unusual resources
5. **Network Analysis** - Port scanning, DDoS, beaconing, DNS tunneling
6. **Rule Engine** - MITRE ATT&CK rule matches
7. **Threat Intel Matching** - Blocked IPs, malicious domains, malware hashes

**Expected output:**
```
Starting COMPREHENSIVE log seeder for 10 minutes
✓ Database schema initialized
✓ Threat intel indicators loaded
[12:34:56] Batch: 10 logs | Elapsed: 0.2m | Remaining: 9.8m | Total: 3 attacks, 7 normal
...
```

### 4. Access the Dashboard

Open your browser and navigate to:
- **Dashboard**: http://localhost:3000/dashboard
- **Alerts**: http://localhost:3000/alerts
- **Logs**: http://localhost:3000/logs
- **Reports**: http://localhost:3000/reports

## System Architecture

```
┌─────────────────┐
│   Frontend      │  http://localhost:3000
│   (Next.js)     │
└────────┬────────┘
         │
         │ HTTP API Calls
         │
┌────────▼────────┐
│   Backend API   │  http://localhost:8000
│   (FastAPI)     │
└────────┬────────┘
         │
         │ Reads/Writes
         │
┌────────▼────────┐
│   DuckDB        │  data/duckdb/logs.db
│   Database      │
└─────────────────┘
         ▲
         │
         │ Writes Logs
         │
┌────────┴────────┐
│   Log Seeder    │  temp_seeder/seeder.py
│   (Python)      │
└─────────────────┘
```

## Detection Methods Explained

### 1. Signature Detection
- **Triggers**: SQL injection patterns, XSS, path traversal, command injection
- **Example logs**: `' OR 1=1--`, `<script>alert(1)</script>`, `../../../etc/passwd`
- **View**: Alerts page → Filter by "Signature Detection"

### 2. Anomaly Detection
- **Triggers**: Statistical deviations from baseline (z-score > 3)
- **Example patterns**: 
  - High login frequency (50+ logins/hour)
  - Failed login spike (20+ failures in 5 minutes)
  - Unusual request patterns
- **View**: Dashboard → Anomaly Detection section

### 3. Heuristic Analysis
- **Triggers**: Rule-of-thumb attack patterns
- **Example patterns**:
  - **Brute Force**: 5+ failed logins followed by success
  - **Privilege Escalation**: sudo/root access shortly after login
  - **Lateral Movement**: Accessing 5+ different hosts in 15 minutes
  - **Data Exfiltration**: 100MB+ transfer to external IP
  - **Off-Hours Activity**: Logins between 22:00-06:00
  - **Rapid File Access**: 20+ file accesses in 5 minutes
  - **Suspicious Commands**: `rm -rf`, `chmod 777`, `wget`, `nc`
- **View**: Alerts page → Filter by "Heuristic Analysis"

### 4. Behavioral Analysis (UEBA)
- **Triggers**: Deviations from user's normal behavior
- **Example patterns**:
  - **Unusual Login Time**: Login at hour user never logs in
  - **Unusual Source IP**: Login from IP user never used
  - **Unusual Resource**: Accessing resources user never accessed
- **View**: Alerts page → Filter by "Behavioral Analysis"

### 5. Network Analysis
- **Triggers**: Network traffic anomalies
- **Example patterns**:
  - **Port Scanning**: 20+ unique ports scanned in 1 minute
  - **DDoS**: 1000+ connections to single destination in 1 minute
  - **Beaconing**: Regular periodic connections (C2 communication)
  - **DNS Tunneling**: 100+ DNS queries per minute
  - **Protocol Anomalies**: HTTP on non-standard ports
  - **Bandwidth Anomalies**: 100MB+ transfer in 5 minutes
- **View**: Alerts page → Filter by "Network Analysis"

### 6. Rule Engine
- **Triggers**: MITRE ATT&CK rule matches
- **Example rules**:
  - **T1110 - Brute Force**: 10+ failed logins from same IP in 5 minutes
  - **T1078 - Valid Accounts**: Privileged user login from external IP
  - **T1071 - C2 Protocol**: 50+ connections to suspicious ports
- **View**: Alerts page → Filter by "Rule Engine"

### 7. Threat Intel Matching
- **Triggers**: Indicators matching threat intelligence feeds
- **Example indicators**:
  - **Blocked IPs**: Connections from known malicious IPs
  - **Malicious Domains**: DNS queries to known bad domains
  - **Malware Hashes**: File hashes matching known malware
- **View**: Alerts page → Filter by "Threat Intel"

## Viewing Results

### Dashboard
- **URL**: http://localhost:3000/dashboard
- **Shows**:
  - Total logs and alerts
  - Alert severity distribution
  - Top hosts and alert types
  - Anomaly detection trends
  - Real-time statistics (auto-refreshes every 10 seconds)

### Alerts Page
- **URL**: http://localhost:3000/alerts
- **Features**:
  - Filter by severity (Critical, High, Medium, Low)
  - Filter by detection method
  - Expand alerts to see **causation information**:
    - What triggered the alert
    - Detection method details
    - Related log entry
    - Statistical deviations (for anomalies)
    - Rule IDs (for rule engine)
    - Threat intel indicators
- **Causation Info Examples**:
  - Signature: Shows matched pattern and signature ID
  - Anomaly: Shows z-score, baseline vs observed values
  - Heuristic: Shows rule name, pattern details
  - Behavioral: Shows deviation type and typical vs unusual
  - Network: Shows ports scanned, connection counts
  - Rule Engine: Shows MITRE technique and tactic
  - Threat Intel: Shows indicator type and threat type

### Logs Page
- **URL**: http://localhost:3000/logs
- **Features**:
  - Search logs by keyword
  - Filter by application and host
  - View detailed log information
  - Export logs to CSV
  - Auto-refresh option

### Reports Page
- **URL**: http://localhost:3000/reports
- **Shows**:
  - Time-based statistics (24h, 7d)
  - Detection method breakdown
  - Alert type distribution
  - Anomaly detection report with trends
  - Severity breakdown

## API Endpoints

The backend provides REST API endpoints:

- `GET /api/v1/stats` - Dashboard statistics
- `GET /api/v1/alerts` - List alerts with causation info
- `GET /api/v1/alerts/{id}` - Get specific alert with full details
- `GET /api/v1/logs` - List logs with filtering
- `GET /api/v1/alerts/stats` - Detailed alert statistics
- `GET /api/v1/anomalies/trend` - Anomaly trend data

## Troubleshooting

### Database Lock Errors
If you see database lock errors when running the seeder:

**Solution 1**: Stop the API temporarily
```bash
# Stop API (Ctrl+C), then run seeder
python temp_seeder/seeder.py 10 1.0 10
# Restart API after seeding
```

**Solution 2**: Run seeder when API is not running
- The seeder will automatically retry on lock conflicts
- Wait a few seconds between batches

### No Alerts Appearing
1. **Check if analysis is running**: Look for "Analysis cycle completed" in API logs
2. **Wait for analysis cycle**: Analysis runs every 60 seconds
3. **Check logs were generated**: Verify logs exist in database
4. **Check detection methods**: Ensure seeder generated logs for all methods

### Frontend Not Loading
1. **Check API is running**: Verify http://localhost:8000/api/v1/health
2. **Check CORS**: API allows localhost:3000 and localhost:3001
3. **Check browser console**: Look for API connection errors

### Alerts Not Showing Causation Info
1. **Check API version**: Ensure you're using the updated API with causation endpoints
2. **Check alert metadata**: Causation info is in `causation_info` field
3. **Refresh page**: Clear cache and reload

## Seeder Options

### Quick Test (2 minutes)
```bash
python seeder.py 5 0.5 2
```

### Full Test (10 minutes) - Recommended
```bash
python seeder.py 10 1.0 10
```

### Extended Test (30 minutes)
```bash
python seeder.py 20 1.0 30
```

### Custom Configuration
```bash
python seeder.py <batch_size> <interval_seconds> <duration_minutes>
```

## Verification Checklist

After running the seeder for 10 minutes, verify:

- [ ] Dashboard shows alerts (check total_alerts > 0)
- [ ] Alerts page shows alerts from all 7 detection methods
- [ ] Each alert shows causation information when expanded
- [ ] Anomaly detection section on dashboard has data
- [ ] Reports page shows detection method breakdown
- [ ] Logs page shows generated logs
- [ ] All detection methods appear in alerts filter dropdown

## Next Steps

1. **Explore Alerts**: Click on alerts to see detailed causation information
2. **Filter by Method**: Use the detection method filter to see specific types
3. **View Reports**: Check the reports page for comprehensive statistics
4. **Analyze Trends**: Look at anomaly trends on the dashboard
5. **Export Data**: Export logs and reports for further analysis

## System Status

Check system health:
```bash
curl http://localhost:8000/api/v1/health
```

Check API root:
```bash
curl http://localhost:8000/
```

## Support

For issues or questions:
1. Check the logs in the terminal where API is running
2. Check browser console for frontend errors
3. Verify database file exists: `data/duckdb/logs.db`
4. Ensure all dependencies are installed

---

**Happy Analyzing! 🚀**

