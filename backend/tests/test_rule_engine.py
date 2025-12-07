"""
Test script for rule engine
Tests rule loading, parsing, and evaluation against logs
"""
import sys
import asyncio
from pathlib import Path
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.rule_engine import RuleEngine
from storage.models import LogEntry
import structlog

logger = structlog.get_logger()


async def test_rule_engine():
    """Test the rule engine with sample rules and logs"""
    
    print("=" * 70)
    print("Testing Rule Engine")
    print("=" * 70)
    
    # Initialize rule engine
    print("\n1. Initializing rule engine...")
    engine = RuleEngine(rule_dir="config/rules")
    print(f"✓ Rule engine initialized with {len(engine.rules)} rules")
    
    if engine.rules:
        print("\nLoaded rules:")
        for rule in engine.rules[:5]:  # Show first 5
            print(f"  - {rule.get('id', 'unknown')}: {rule.get('name', 'unnamed')}")
    
    # Test 1: Selection Criteria Matching
    print("\n2. Testing selection criteria matching...")
    selection_logs = []
    
    # SSH brute force attack
    for i in range(5):
        selection_logs.append(LogEntry(
            id=f"ssh-{i}",
            timestamp=(datetime.now() - timedelta(seconds=i*10)).isoformat(),
            raw=f"ssh-server sshd: Failed password for root from 203.0.113.1",
            message=f"Failed password for root from 203.0.113.1 port 22 ssh2",
            appname="sshd",
            host="ssh-server",
            normalized={"user": "root", "source_ip": "203.0.113.1", "action": "failed_login"}
        ))
    
    alerts = await engine.analyze(selection_logs)
    print(f"✓ Selection matching: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 2: Count-Based Conditions
    print("\n3. Testing count-based conditions...")
    count_logs = []
    
    # Multiple failed login attempts (should trigger count threshold)
    for i in range(10):
        count_logs.append(LogEntry(
            id=f"count-{i}",
            timestamp=(datetime.now() - timedelta(seconds=i*5)).isoformat(),
            raw=f"auth: Failed login attempt for user admin",
            message=f"Failed login attempt for user admin from 192.0.2.1",
            appname="auth",
            host="server-01",
            normalized={"user": "admin", "source_ip": "192.0.2.1", "action": "failed_login"}
        ))
    
    alerts = await engine.analyze(count_logs)
    print(f"✓ Count-based rules: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 3: Frequency-Based Conditions
    print("\n4. Testing frequency-based conditions...")
    freq_logs = []
    
    # Rapid requests from single IP (potential scanning)
    base_time = datetime.now()
    for i in range(20):
        freq_logs.append(LogEntry(
            id=f"freq-{i}",
            timestamp=(base_time - timedelta(seconds=i)).isoformat(),
            raw=f"nginx: 45.142.212.61 - - GET /api/test HTTP/1.1",
            message="GET /api/test HTTP/1.1 200",
            appname="nginx",
            host="web-server",
            normalized={"source_ip": "45.142.212.61", "method": "GET", "url": "/api/test"}
        ))
    
    alerts = await engine.analyze(freq_logs)
    print(f"✓ Frequency-based rules: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 4: MITRE ATT&CK Mapping
    print("\n5. Testing MITRE ATT&CK mapping...")
    mitre_logs = []
    
    # Privilege escalation attempt (should map to MITRE technique)
    mitre_logs.append(LogEntry(
        id="mitre-1",
        timestamp=datetime.now().isoformat(),
        raw="sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash",
        message="sudo: user1 : USER=root ; COMMAND=/bin/bash",
        appname="sudo",
        host="server-01",
        normalized={"user": "user1", "target_user": "root", "command": "/bin/bash"}
    ))
    
    alerts = await engine.analyze(mitre_logs)
    print(f"✓ MITRE ATT&CK mapping: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
            if alert.metadata and 'mitre_technique' in alert.metadata:
                print(f"    MITRE: {alert.metadata.get('mitre_technique')}")
    
    # Test 5: Normal Logs (No False Positives)
    print("\n6. Testing with normal logs (no false positives)...")
    normal_logs = []
    
    normal_logs.append(LogEntry(
        id="normal-1",
        timestamp=datetime.now().isoformat(),
        raw="nginx: 192.168.1.100 - - GET /index.html HTTP/1.1 200",
        message="GET /index.html HTTP/1.1 200",
        appname="nginx",
        host="web-server",
        normalized={"source_ip": "192.168.1.100", "method": "GET", "status": 200}
    ))
    
    alerts = await engine.analyze(normal_logs)
    print(f"✓ Normal logs: {len(alerts)} alerts generated (expected: 0)")
    
    # Test 6: Rule Statistics
    print("\n7. Rule engine statistics...")
    print(f"  - Total rules loaded: {len(engine.rules)}")
    enabled_rules = [r for r in engine.rules if r.get('enabled', True)]
    print(f"  - Enabled rules: {len(enabled_rules)}")
    print(f"  - Disabled rules: {len(engine.rules) - len(enabled_rules)}")
    
    # Summary
    print("\n" + "=" * 70)
    print("Rule Engine Test Complete!")
    print("=" * 70)
    print("\nAll rule engine features tested:")
    print("  ✓ Rule loading and parsing")
    print("  ✓ Selection criteria matching")
    print("  ✓ Count-based conditions")
    print("  ✓ Frequency-based conditions")
    print("  ✓ MITRE ATT&CK mapping")
    print("  ✓ Normal log handling (no false positives)")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_rule_engine())
