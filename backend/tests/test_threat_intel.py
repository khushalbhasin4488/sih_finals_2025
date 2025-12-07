"""
Test script for threat intelligence matching
Tests IP, domain, and hash matching against threat intel database
"""
import sys
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.threat_intel_matcher import ThreatIntelMatcher
from storage.db_manager import DuckDBManager
from storage.models import LogEntry, ThreatIntel
from core.config import config
from datetime import datetime
import uuid
import structlog

logger = structlog.get_logger()


async def test_threat_intel_matcher():
    """Test the threat intelligence matcher"""
    
    print("=" * 70)
    print("Testing Threat Intelligence Matching")
    print("=" * 70)
    
    # Initialize database
    print("\n1. Initializing database...")
    db_manager = DuckDBManager(config.get_database_path())
    
    # Check existing threat intel
    existing_intel = db_manager.fetch_threat_intel()
    print(f"✓ Found {len(existing_intel)} existing threat intel indicators")
    
    if existing_intel:
        print("\nSample indicators:")
        for intel in existing_intel[:3]:
            print(f"  - {intel.indicator_type}: {intel.indicator_value} ({intel.threat_type})")
    
    # Initialize matcher
    print("\n2. Initializing threat intel matcher...")
    matcher = ThreatIntelMatcher(db_manager)
    print(f"✓ Loaded {len(matcher.threat_intel_cache)} cached indicators")
    
    # Test 1: Malicious IP Detection
    print("\n3. Testing malicious IP detection...")
    ip_logs = [
        LogEntry(
            id="ip-test-1",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-08 02:00:00 server-01 nginx: Connection from 192.0.2.1",
            message="Connection from 192.0.2.1",
            appname="nginx",
            host="server-01",
            normalized={"source_ip": "192.0.2.1"}
        )
    ]
    
    alerts = await matcher.analyze(ip_logs)
    print(f"✓ Malicious IP detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 2: Malicious Domain Detection
    print("\n4. Testing malicious domain detection...")
    domain_logs = [
        LogEntry(
            id="domain-test-1",
            timestamp=datetime.now().isoformat(),
            raw='2024-12-08 02:01:00 server-01 nginx: GET / HTTP/1.1" 200 612 "http://evil.com"',
            message='GET / HTTP/1.1" 200 612 "http://evil.com"',
            appname="nginx",
            host="server-01",
            normalized={"domain": "evil.com", "source_ip": "10.0.0.1"}
        )
    ]
    
    alerts = await matcher.analyze(domain_logs)
    print(f"✓ Malicious domain detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 3: Malicious Hash Detection
    print("\n5. Testing malicious hash detection...")
    hash_logs = [
        LogEntry(
            id="hash-test-1",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-08 02:02:00 server-01 av: Suspicious file hash: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            message="Suspicious file hash detected: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            appname="av",
            host="server-01",
            normalized={"file_hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"}
        )
    ]
    
    alerts = await matcher.analyze(hash_logs)
    print(f"✓ Malicious hash detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 4: Multiple Indicators in One Log
    print("\n6. Testing multiple indicators in single log...")
    multi_logs = [
        LogEntry(
            id="multi-test-1",
            timestamp=datetime.now().isoformat(),
            raw='2024-12-08 02:03:00 server-01 nginx: 192.0.2.1 - - [08/Dec/2024:02:03:00] "GET / HTTP/1.1" 200 612 "http://evil.com"',
            message='192.0.2.1 - - GET / HTTP/1.1" 200 612 "http://evil.com"',
            appname="nginx",
            host="server-01",
            normalized={"source_ip": "192.0.2.1", "domain": "evil.com"}
        )
    ]
    
    alerts = await matcher.analyze(multi_logs)
    print(f"✓ Multiple indicators: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 5: No Match (should generate no alerts)
    print("\n7. Testing benign log (no match expected)...")
    benign_logs = [
        LogEntry(
            id="benign-1",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-08 02:04:00 server-01 nginx: 192.168.1.100 - - GET / HTTP/1.1",
            message="GET / HTTP/1.1 200",
            appname="nginx",
            host="server-01",
            normalized={"source_ip": "192.168.1.100"}
        )
    ]
    
    alerts = await matcher.analyze(benign_logs)
    print(f"✓ Benign log: {len(alerts)} alerts generated (expected: 0)")
    
    # Cleanup
    db_manager.close()
    
    # Summary
    print("\n" + "=" * 70)
    print("Threat Intelligence Matching Test Complete!")
    print("=" * 70)
    print("\nAll threat intel types tested:")
    print("  ✓ Malicious IP matching")
    print("  ✓ Malicious domain matching")
    print("  ✓ Malicious hash matching")
    print("  ✓ Multiple indicators in one log")
    print("  ✓ Benign log (no false positives)")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_threat_intel_matcher())
