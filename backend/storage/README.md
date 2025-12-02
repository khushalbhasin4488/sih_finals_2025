# Database Connection Layer - Implementation Summary

## Completed Components

### 1. Data Models (`storage/models.py`)
- **LogEntry**: Flexible model to handle different log formats from various services
  - Supports variable fields (appname, host, hostname, message, etc.)
  - JSON fields for normalized data and metadata
  - Helper methods: `get_timestamp()`, `get_source_ip()`, `get_user()`
  - Handles different timestamp formats

- **Alert**: Security alert model with priority scoring
- **ThreatIntel**: Threat intelligence indicators
- **DetectionRule**: Detection rule definitions

### 2. Database Manager (`storage/db_manager.py`)
- **DuckDBManager**: Main database interface
  - Connection management with context managers
  - Flexible schema initialization
  - Indexed tables for performance

#### Key Methods:
- `fetch_logs()`: Fetch logs with time range and filters
- `fetch_recent_logs()`: Get logs from last N minutes
- `count_logs()`: Count logs matching criteria
- `store_alert()`: Store single alert
- `store_alerts_batch()`: Batch alert storage
- `fetch_alerts()`: Retrieve alerts with filters
- `execute_query()`: Execute custom SQL queries

### 3. Configuration Management (`core/config.py`)
- **ConfigManager**: Loads settings from YAML and environment
- **Settings**: Pydantic-based settings with validation
- Supports dot notation for nested config access

### 4. Logging (`core/logger.py`)
- Structured logging with `structlog`
- JSON output for production
- Console output for development

### 5. Periodic Log Fetcher (`core/periodic_fetcher.py`)
- **PeriodicLogFetcher**: Fetches logs at regular intervals
  - Configurable interval (default: 60 seconds)
  - Callback system for processing fetched logs
  - Async/await support
  - Automatic time tracking between fetches

### 6. Testing (`tests/test_db_connection.py`)
- Database connection test script
- Validates all major operations
- Sample data retrieval examples

## Database Schema

```sql
-- Logs table (flexible schema)
CREATE TABLE logs (
    id VARCHAR PRIMARY KEY,
    timestamp VARCHAR,
    raw VARCHAR,
    appname VARCHAR,
    file VARCHAR,
    host VARCHAR,
    hostname VARCHAR,
    message VARCHAR,
    procid INTEGER,
    source_type VARCHAR,
    normalized JSON,
    metadata JSON,
    ingestion_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts table
CREATE TABLE alerts (
    id VARCHAR PRIMARY KEY,
    log_id VARCHAR,
    alert_type VARCHAR,
    detection_method VARCHAR,
    severity VARCHAR,
    description VARCHAR,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE,
    priority_score DOUBLE,
    source_ip VARCHAR,
    dest_ip VARCHAR,
    user VARCHAR,
    host VARCHAR
);

-- Threat intelligence table
CREATE TABLE threat_intel (
    id VARCHAR PRIMARY KEY,
    indicator_type VARCHAR,
    indicator_value VARCHAR,
    threat_type VARCHAR,
    confidence DOUBLE,
    source VARCHAR,
    metadata JSON,
    created_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Detection rules table
CREATE TABLE detection_rules (
    id VARCHAR PRIMARY KEY,
    rule_name VARCHAR,
    rule_type VARCHAR,
    rule_definition JSON,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

## Usage Examples

### Basic Connection
```python
from storage.db_manager import DuckDBManager
from core.config import config

db_manager = DuckDBManager(config.get_database_path())
```

### Fetch Recent Logs
```python
# Get logs from last 1 minute
recent_logs = db_manager.fetch_recent_logs(minutes=1)

for log in recent_logs:
    print(f"Host: {log.host}, Message: {log.message}")
    print(f"Source IP: {log.get_source_ip()}")
    print(f"User: {log.get_user()}")
```

### Fetch with Filters
```python
# Get SSH logs from specific host
logs = db_manager.fetch_logs(
    filters={'appname': 'sshd', 'host': 'server1'},
    limit=100
)
```

### Periodic Fetching
```python
from core.periodic_fetcher import PeriodicLogFetcher

async def process_logs(logs):
    print(f"Processing {len(logs)} logs")
    # Your analysis logic here

fetcher = PeriodicLogFetcher(db_manager, interval_seconds=60)
fetcher.register_callback(process_logs)
await fetcher.start()
```

### Store Alerts
```python
from storage.models import Alert, Severity
import uuid

alert = Alert(
    id=str(uuid.uuid4()),
    alert_type="brute_force",
    detection_method="heuristic",
    severity=Severity.HIGH,
    description="Multiple failed login attempts detected",
    source_ip="159.223.208.40",
    user="admin"
)

db_manager.store_alert(alert)
```

## Next Steps

The database layer is now ready for integration with:
1. **Analysis Engine**: Can fetch logs and store alerts
2. **API Layer**: Can query logs and alerts for the frontend
3. **Detection Methods**: Can process logs in batches

## Testing

Run the test script:
```bash
cd backend
python tests/test_db_connection.py
```

This will verify:
- Database connection
- Log counting
- Recent log fetching
- Filtered queries
- Alert storage
