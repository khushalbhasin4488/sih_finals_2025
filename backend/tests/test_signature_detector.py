"""
Test script for signature-based detection
"""
import sys
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.signature_detector import SignatureDetector
from storage.models import LogEntry
from datetime import datetime
import structlog

logger = structlog.get_logger()


async def test_signature_detector():
    """Test the signature detector with sample logs"""
    
    print("=" * 70)
    print("Testing Signature-Based Detection")
    print("=" * 70)
    
    # Initialize detector
    print("\n1. Initializing signature detector...")
    detector = SignatureDetector(
        signature_dir="config/signatures",
        blocked_ips_file="config/blocked_ips.txt"
    )
    print(f"✓ Loaded {len(detector.signatures)} signatures")
    print(f"✓ Loaded {len(detector.blocked_ips)} blocked IPs")
    print(f"✓ Loaded {len(detector.hash_signatures)} hash signatures")
    
    # Create test logs
    print("\n2. Creating test logs...")
    test_logs = [
        # SQL Injection
        LogEntry(
            id="test-001",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-07 14:00:00 web-server nginx: GET /api/users?id=1' OR '1'='1 HTTP/1.1",
            message="GET /api/users?id=1' OR '1'='1 HTTP/1.1",
            appname="nginx",
            host="web-server",
            hostname="web-server",
            normalized={"query_string": "id=1' OR '1'='1"}
        ),
        # XSS Attack
        LogEntry(
            id="test-002",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-07 14:01:00 web-server nginx: POST /comment <script>alert('XSS')</script>",
            message="POST /comment <script>alert('XSS')</script>",
            appname="nginx",
            host="web-server",
            hostname="web-server",
            normalized={"user_input": "<script>alert('XSS')</script>"}
        ),
        # SSH Brute Force
        LogEntry(
            id="test-003",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-07 14:02:00 ssh-server sshd: Failed password for admin from 192.0.2.1 port 22",
            message="Failed password for admin from 192.0.2.1 port 22",
            appname="sshd",
            host="ssh-server",
            hostname="ssh-server"
        ),
        # Blocked IP
        LogEntry(
            id="test-004",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-07 14:03:00 web-server nginx: Connection from 192.0.2.1",
            message="Connection from 192.0.2.1",
            appname="nginx",
            host="web-server",
            hostname="web-server"
        ),
        # Command Injection
        LogEntry(
            id="test-005",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-07 14:04:00 web-server app: Command: ping -c 1 127.0.0.1; cat /etc/passwd",
            message="Command: ping -c 1 127.0.0.1; cat /etc/passwd",
            appname="app",
            host="web-server",
            hostname="web-server",
            normalized={"command": "ping -c 1 127.0.0.1; cat /etc/passwd"}
        ),
        # Mimikatz
        LogEntry(
            id="test-006",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-07 14:05:00 dc-01 security: Process created: mimikatz.exe sekurlsa::logonpasswords",
            message="Process created: mimikatz.exe sekurlsa::logonpasswords",
            appname="security",
            host="dc-01",
            hostname="dc-01",
            normalized={"process_name": "mimikatz.exe", "command": "sekurlsa::logonpasswords"}
        ),
        # Normal log (should not trigger)
        LogEntry(
            id="test-007",
            timestamp=datetime.now().isoformat(),
            raw="2024-12-07 14:06:00 web-server nginx: GET /index.html HTTP/1.1 200",
            message="GET /index.html HTTP/1.1 200",
            appname="nginx",
            host="web-server",
            hostname="web-server"
        )
    ]
    
    print(f"✓ Created {len(test_logs)} test logs")
    
    # Run detection
    print("\n3. Running signature detection...")
    alerts = await detector.analyze(test_logs)
    
    print(f"\n✓ Detection complete: {len(alerts)} alerts generated")
    
    # Display results
    print("\n4. Alert Details:")
    print("-" * 70)
    
    if not alerts:
        print("No alerts generated")
    else:
        for i, alert in enumerate(alerts, 1):
            print(f"\nAlert #{i}:")
            print(f"  Type: {alert.alert_type}")
            print(f"  Severity: {alert.severity}")
            print(f"  Description: {alert.description}")
            print(f"  Log ID: {alert.log_id}")
            print(f"  Host: {alert.host}")
            if alert.source_ip:
                print(f"  Source IP: {alert.source_ip}")
            if alert.metadata:
                print(f"  Metadata: {alert.metadata}")
    
    # Test signature categories
    print("\n5. Signature Categories:")
    print("-" * 70)
    categories = {}
    for sig in detector.signatures:
        cat = sig.get('category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1
    
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count} signatures")
    
    print("\n" + "=" * 70)
    print("Signature Detection Test Complete!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_signature_detector())
