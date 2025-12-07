# Enhanced Log Seeder - Signature + Anomaly Detection

## Overview
Updated seeder generates realistic logs that trigger both signature-based detection and anomaly detection systems.

## Traffic Mix

### 70% Normal Traffic
- Regular SSH connections
- Normal web requests (GET/POST)
- System events
- Database queries
- Legitimate user activity

### 15% Signature Attacks
Individual attack logs that match known signatures:
- **SQL Injection**: `' OR 1=1--`, `UNION SELECT`, `DROP TABLE`
- **XSS**: `<script>alert(1)</script>`, `<img onerror=...>`
- **Path Traversal**: `../../../etc/passwd`
- **Command Injection**: `; cat /etc/passwd`, `| nc attacker.com`
- **Web Shells**: `shell.php`, `c99.php`
- **Malware**: mimikatz, Cobalt Strike, known hashes

### 15% Anomaly Bursts
Bursts of 5-15 logs that trigger anomaly detection:

1. **Brute Force Burst**
   - 5-15 failed login attempts from same IP
   - Triggers: `failed_login_anomaly`, `brute_force_attempt`
   
2. **Request Flood**
   - 5-15 rapid requests from same IP
   - Triggers: `request_rate_anomaly`, `high_request_rate`
   
3. **Error Spike**
   - 5-15 errors in quick succession
   - Triggers: `error_rate_anomaly`
   
4. **Port Scan**
   - 5-15 connection attempts to different ports
   - Triggers: `port_scan_detected`
   
5. **Suspicious Commands**
   - Multiple dangerous command executions
   - Triggers: `command_execution_anomaly`, `suspicious_commands`

## Attacker IPs

**Dedicated Attacker IPs** (for anomaly bursts):
- `203.0.113.50`
- `198.51.100.75`
- `192.0.2.100`

**Blocked IPs** (from threat intel):
- `192.0.2.1`
- `198.51.100.1`
- `203.0.113.1`
- `185.220.101.1`
- `185.220.101.2`
- `45.142.212.61`

## Usage

### Basic Usage
```bash
# Generate 10 logs every 2 seconds
python3 temp_seeder/seeder.py 10 2
```

### High Volume
```bash
# Generate 50 logs every 1 second
python3 temp_seeder/seeder.py 50 1
```

### Slow Testing
```bash
# Generate 5 logs every 5 seconds
python3 temp_seeder/seeder.py 5 5
```

## Output Example

```
[16:50:15] Inserted 10 logs (7 normal, 2 signature, 1 anomaly) | Total: 70N 20S 10A
[16:50:17] Inserted 10 logs (6 normal, 1 signature, 3 anomaly) | Total: 76N 21S 13A
[16:50:19] Inserted 10 logs (8 normal, 2 signature, 0 anomaly) | Total: 84N 23S 13A
```

Legend:
- **N** = Normal logs
- **S** = Signature attack logs
- **A** = Anomaly burst logs

## Expected Detections

### Signature Detector Will Catch:
- SQL injection patterns
- XSS attempts
- Path traversal
- Command injection
- Web shells
- Malware indicators
- Blocked IP connections

### Anomaly Detector Will Catch:
- Unusual login frequency
- Failed login spikes (brute force)
- Request rate anomalies
- Error rate spikes
- Port scanning activity
- Suspicious command execution

## Testing Both Systems

### 1. Start Backend API
```bash
cd backend
source .venv/bin/activate
python3 -m uvicorn api.main:app --reload
```

### 2. Start Orchestrator (Optional)
```bash
cd backend
source .venv/bin/activate
python3 tests/test_orchestrator.py
```

### 3. Start Seeder
```bash
python3 temp_seeder/seeder.py 20 3
```

### 4. View Results
- **Frontend**: http://localhost:3000/alerts
- **API**: http://localhost:8000/api/v1/alerts

## Verification

### Check Signature Detections
```bash
curl "http://localhost:8000/api/v1/alerts?limit=10" | jq '.[] | select(.detection_method=="signature_detection")'
```

### Check Anomaly Detections
```bash
curl "http://localhost:8000/api/v1/alerts?limit=10" | jq '.[] | select(.detection_method=="anomaly_detection")'
```

### Count by Method
```bash
curl "http://localhost:8000/api/v1/alerts/stats" | jq '.detection_methods'
```

## Anomaly Burst Examples

### Brute Force Burst (5-15 logs)
```
Failed password for admin from 203.0.113.50 port 52341 ssh2
Failed password for root from 203.0.113.50 port 52342 ssh2
Failed password for user from 203.0.113.50 port 52343 ssh2
...
```
**Triggers**: Z-score anomaly on failed_login_rate

### Request Flood (5-15 logs)
```
203.0.113.50 - - [07/Dec/2025:16:50:15 +0000] "GET /api/data HTTP/1.1" 200 45
203.0.113.50 - - [07/Dec/2025:16:50:15 +0000] "POST /api/submit HTTP/1.1" 201 23
203.0.113.50 - - [07/Dec/2025:16:50:15 +0000] "GET /api/status HTTP/1.1" 200 12
...
```
**Triggers**: Z-score anomaly on requests_per_ip

### Port Scan Burst (5-15 logs)
```
UFW BLOCK: IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP SPT=54321 DPT=22
UFW BLOCK: IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.11 PROTO=TCP SPT=54322 DPT=80
UFW BLOCK: IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.12 PROTO=TCP SPT=54323 DPT=443
...
```
**Triggers**: Pattern-based port scan detection (10+ unique destinations)

## Benefits

1. **Realistic Testing**: Mix of normal and malicious traffic
2. **Both Detection Methods**: Tests signature and anomaly systems
3. **Baseline Building**: Normal traffic helps establish baselines
4. **Burst Patterns**: Anomaly bursts mimic real attack patterns
5. **Visual Verification**: See detections in frontend alerts page

## Troubleshooting

**No anomaly alerts**:
- Baselines may not be established yet
- Run seeder for 5-10 minutes to build baseline
- Check `data/baselines.json` exists

**No signature alerts**:
- Verify orchestrator is running
- Check signature files in `config/signatures/`
- Ensure API is connected to correct database

**Too many false positives**:
- Reduce anomaly burst frequency
- Increase normal traffic percentage
- Adjust thresholds in anomaly detector

## Files Modified

- `temp_seeder/seeder.py` - Complete rewrite with dual detection support
