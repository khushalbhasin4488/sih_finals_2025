# Example Log Ingestion Payload

This directory contains example files for testing the log ingestion pipeline.

## Files

### `example_ingestion_payload.json`

A sample JSON payload containing **20 diverse log entries** that can be used to test the ingestion route and dashboard analysis.

## Log Entry Schema

Each log entry follows this schema:

```json
{
  "id": "string (unique identifier)",
  "timestamp": "ISO 8601 format (e.g., 2025-12-08T11:45:00.000000)",
  "host": "string (server hostname)",
  "source_type": "string (auth|web|system|firewall|database)",
  "appname": "string (sshd|nginx|systemd|iptables|postgresql)",
  "message": "string (raw log message)",
  "source_ip": "string (optional, source IP address)",
  "user": "string (optional, username for auth logs)",
  "event_type": "string (optional, login_success|login_failed)"
}
```

## Sample Log Types Included

1. **Web Logs (nginx)**
   - Normal HTTP requests
   - SQL injection attempts (`' OR '1'='1`)
   - Path traversal attacks (`../../../etc/passwd`)
   - XSS attempts (`<script>alert('xss')</script>`)

2. **Auth Logs (sshd)**
   - Successful logins
   - Failed login attempts (brute force patterns)
   - Multiple failed attempts from same IP

3. **System Logs (systemd)**
   - User manager events
   - Disk usage warnings
   - Connection closures

4. **Firewall Logs (iptables)**
   - SYN packets on various ports
   - Suspicious traffic patterns

5. **Database Logs (postgresql)**
   - Connection events
   - Authentication failures

## Usage with Ingestion Route

### POST to Temporary Endpoint

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d @data/example_ingestion_payload.json
```

### Python Example

```python
import requests
import json

# Load the sample payload
with open('data/example_ingestion_payload.json', 'r') as f:
    logs = json.load(f)

# Post to ingestion endpoint
response = requests.post(
    'http://localhost:8000/api/ingest',
    json=logs,
    headers={'Content-Type': 'application/json'}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.json()}")
```

## Dashboard Analysis

After ingestion, these logs will:
1. Be stored in DuckDB for persistence
2. Trigger **signature-based detection** for known attack patterns
3. Feed into **anomaly detection** for unusual behavior patterns
4. Appear in the dashboard with appropriate alerts

## Customizing the Payload

To add more logs, follow the schema above and append to the JSON array. Ensure:
- Each `id` is unique
- Timestamps are in ISO 8601 format
- `source_type` matches one of: `auth`, `web`, `system`, `firewall`, `database`
