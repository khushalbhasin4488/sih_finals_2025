import sys
import os
import time
import random
import json
import uuid
import duckdb
from datetime import datetime, timedelta

# Add backend to path to import models if needed, but we'll use direct SQL for simplicity and speed
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend'))

DB_PATH = "data/duckdb/logs.db"

# Sample data for generation
HOSTS = [f"server-{i:02d}" for i in range(1, 21)]
APPS = ["sshd", "nginx", "apache2", "mysql", "postgresql", "kernel", "systemd", "cron"]
USERS = ["root", "admin", "user", "deploy", "backup", "guest", "ubuntu", "ec2-user"]
IPS = [f"192.168.1.{i}" for i in range(1, 255)] + [f"10.0.0.{i}" for i in range(1, 255)]
EXTERNAL_IPS = [f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(50)]

MESSAGES = {
    "sshd": [
        "Accepted publickey for {user} from {ip} port {port} ssh2",
        "Failed password for {user} from {ip} port {port} ssh2",
        "Disconnected from {ip} port {port}",
        "Invalid user {user} from {ip}",
        "Connection closed by {ip} port {port} [preauth]"
    ],
    "nginx": [
        '{ip} - - [{timestamp}] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"',
        '{ip} - - [{timestamp}] "POST /api/login HTTP/1.1" 401 124 "-" "curl/7.68.0"',
        '{ip} - - [{timestamp}] "GET /admin HTTP/1.1" 403 168 "-" "Mozilla/5.0"',
        '{ip} - - [{timestamp}] "GET /static/style.css HTTP/1.1" 200 1456 "http://example.com" "Mozilla/5.0"'
    ],
    "kernel": [
        "UFW BLOCK: IN=eth0 OUT= MAC=... SRC={ip} DST=... PROTO=TCP SPT={port} DPT=22",
        "Out of memory: Kill process {pid} (python3) score 851 or sacrifice child",
        "segfault at 0 ip ... sp ... error 4 in libc-2.31.so"
    ]
}

def connect_db():
    # Ensure directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return duckdb.connect(DB_PATH)

def generate_log():
    app = random.choice(APPS)
    host = random.choice(HOSTS)
    
    # Determine IP based on context
    if random.random() < 0.2:
        ip = random.choice(EXTERNAL_IPS)
    else:
        ip = random.choice(IPS)
        
    user = random.choice(USERS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    # Generate message
    if app in MESSAGES:
        template = random.choice(MESSAGES[app])
        timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        message = template.format(
            user=user, ip=ip, port=port, pid=pid, timestamp=timestamp_str
        )
    else:
        message = f"Generic log message from {app} process {pid}"
        
    # Create log entry
    log_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    # Normalized data
    normalized = {
        "timestamp": timestamp,
        "appname": app,
        "host": host,
        "message": message,
        "source_ip": ip,
        "user": user if app == "sshd" else None
    }
    
    return {
        "id": log_id,
        "timestamp": timestamp,
        "raw": f"{timestamp} {host} {app}[{pid}]: {message}",
        "appname": app,
        "file": f"/var/log/{app}.log",
        "host": host,
        "hostname": host,
        "message": message,
        "procid": pid,
        "source_type": "file",
        "normalized": json.dumps(normalized),
        "metadata": json.dumps({"environment": "production", "region": "us-east-1"}),
        "ingestion_time": datetime.now()
    }

def seed_logs(batch_size=10, interval=1.0):
    print(f"Starting log seeder. Writing to {DB_PATH}")
    print(f"Batch size: {batch_size}, Interval: {interval}s")
    print("Press Ctrl+C to stop")
    print("Note: Connection is opened/closed per batch to allow concurrent access")
    
    try:
        while True:
            # Open connection for this batch
            conn = connect_db()
            
            try:
                logs = [generate_log() for _ in range(batch_size)]
                
                # Prepare data for insertion
                # Columns: id, timestamp, raw, appname, file, host, hostname, message, procid, source_type, normalized, metadata, ingestion_time
                data = []
                for log in logs:
                    data.append((
                        log["id"], log["timestamp"], log["raw"], log["appname"], 
                        log["file"], log["host"], log["hostname"], log["message"], 
                        log["procid"], log["source_type"], log["normalized"], 
                        log["metadata"], log["ingestion_time"]
                    ))
                
                # Insert batch
                placeholders = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                conn.executemany(f"""
                    INSERT INTO logs (
                        id, timestamp, raw, appname, file, host, hostname, 
                        message, procid, source_type, normalized, metadata, ingestion_time
                    ) VALUES {placeholders}
                """, data)
                
                print(f"Inserted {batch_size} logs at {datetime.now().strftime('%H:%M:%S')}")
                
            finally:
                # Close connection after each batch to allow other processes to access
                conn.close()
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nStopping seeder...")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        print("Seeder stopped")

if __name__ == "__main__":
    # Optional arguments: batch_size, interval
    batch_size = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    
    seed_logs(batch_size, interval)
