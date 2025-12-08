import json
import random
from datetime import datetime, timedelta
import uuid

def generate_logs(count=200):
    logs = []
    base_time = datetime.now()
    
    # Attack patterns
    ips = {
        'attacker': '203.0.113.45',
        'office': '192.168.1.50',
        'server': '10.0.0.1',
        'random': lambda: f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    }
    
    users = ['admin', 'jdoe', 'service_account', 'root']
    
    for i in range(count):
        # Time distribution (last 2 hours)
        timestamp = base_time - timedelta(minutes=random.randint(0, 120))
        ts_iso = timestamp.isoformat()
        
        # Determine log type
        r = random.random()
        
        log_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": ts_iso,
            "host": "production-server-01"
        }
        
        if i < 50: 
            # Pattern: Brute Force Logs (First 50 logs)
            # Dense failures followed by success
            log_entry['source_type'] = 'auth'
            log_entry['appname'] = 'sshd'
            log_entry['source_ip'] = ips['attacker']
            log_entry['user'] = 'admin'
            
            if i == 49:
                log_entry['message'] = f"Accepted password for admin from {ips['attacker']} port 44322 ssh2"
                log_entry['event_type'] = 'login_success'
            else:
                log_entry['message'] = f"Failed password for admin from {ips['attacker']} port {random.randint(40000, 50000)} ssh2"
                log_entry['event_type'] = 'login_failed'
                
        elif r < 0.4:
            # Web Traffic (Normal + SQLi)
            log_entry['source_type'] = 'web'
            log_entry['appname'] = 'nginx'
            src = ips['random']()
            
            if random.random() < 0.1: # 10% malicious
                payloads = ["' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd"]
                payload = random.choice(payloads)
                log_entry['message'] = f"{src} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET /search?q={payload} HTTP/1.1\" 200 1456"
                log_entry['source_ip'] = src
            else:
                paths = ['/home', '/login', '/api/data', '/assets/style.css']
                log_entry['message'] = f"{src} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET {random.choice(paths)} HTTP/1.1\" 200 {random.randint(500, 5000)}"
                log_entry['source_ip'] = src
                
        elif r < 0.7:
            # Firewall Logs (Port Scan simulation)
            log_entry['source_type'] = 'firewall'
            log_entry['appname'] = 'iptables'
            
            if random.random() < 0.2:
                # Port scan data
                src = ips['attacker']
                dst_port = random.randint(20, 1000)
                log_entry['message'] = f"IN=eth0 OUT= MAC=00:... SRC={src} DST={ips['server']} PROTO=TCP SPT={random.randint(30000,60000)} DPT={dst_port} FLAGS=SYN"
                log_entry['source_ip'] = src
            else:
                log_entry['message'] = f"IN=eth0 OUT= MAC=00:... SRC={ips['random']()} DST={ips['server']} PROTO=TCP SPT={random.randint(30000,60000)} DPT=80 FLAGS=SYN"
        
        else:
            # System logs
            log_entry['source_type'] = 'system'
            log_entry['appname'] = 'systemd'
            log_entry['message'] = random.choice([
                "Started User Manager for UID 1000.",
                "Stopping User Manager for UID 1000.",
                "Disk space usage at 45%",
                "Connection closed by remote host"
            ])

        logs.append(log_entry)
            
    # Sort by time
    logs.sort(key=lambda x: x['timestamp'])
    
    with open('sample_logs_200.json', 'w') as f:
        json.dump(logs, f, indent=2)
        
    print(f"Generated {len(logs)} logs in sample_logs_200.json")

if __name__ == "__main__":
    generate_logs()
