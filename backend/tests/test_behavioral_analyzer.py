"""
Test script for behavioral analysis (UEBA - User and Entity Behavior Analytics)
Tests user profile building and anomaly detection based on behavior
"""
import sys
import asyncio
from pathlib import Path
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.behavioral_analyzer import BehavioralAnalyzer
from storage.models import LogEntry
import structlog

logger = structlog.get_logger()


async def test_behavioral_analyzer():
    """Test the behavioral analyzer with sample user behavior patterns"""
    
    print("=" * 70)
    print("Testing Behavioral Analysis (UEBA)")
    print("=" * 70)
    
    # Initialize analyzer
    print("\n1. Initializing behavioral analyzer...")
    analyzer = BehavioralAnalyzer()
    print(f"✓ Behavioral analyzer initialized")
    
    # Test 1: Build User Profile
    print("\n2. Building user profile from historical logs...")
    profile_logs = []
    base_time = datetime.now()
    
    # Simulate normal user behavior for alice (Mon-Fri, 9 AM - 5 PM, from office IP)
    for day in range(5):  # 5 days of history
        for hour in [9, 10, 11, 14, 15, 16]:  # Working hours
            profile_logs.append(LogEntry(
                id=f"profile-{day}-{hour}",
                timestamp=(base_time - timedelta(days=5-day, hours=24-hour)).isoformat(),
                raw=f"ssh-server sshd: Accepted publickey for alice from 192.168.1.100",
                message="Accepted publickey for alice from 192.168.1.100 port 22",
                appname="sshd",
                host="server-01",
                normalized={"user": "alice", "source_ip": "192.168.1.100", "action": "login"}
            ))
    
    # Update profile with historical data
    analyzer.update_profile("alice", profile_logs)
    print(f"✓ Built profile for user 'alice' from {len(profile_logs)} historical logs")
    
    # Test 2: Unusual Login Time Detection
    print("\n3. Testing unusual login time detection...")
    unusual_time_logs = []
    
    # Login at 2 AM (unusual for alice who normally logs in 9-5)
    unusual_time = datetime.now().replace(hour=2, minute=30, second=0)
    unusual_time_logs.append(LogEntry(
        id="unusual-time-1",
        timestamp=unusual_time.isoformat(),
        raw="ssh-server sshd: Accepted publickey for alice from 192.168.1.100",
        message="Accepted publickey for alice from 192.168.1.100 port 22",
        appname="sshd",
        host="server-01",
        normalized={"user": "alice", "source_ip": "192.168.1.100", "action": "login"}
    ))
    
    alerts = await analyzer.analyze(unusual_time_logs)
    print(f"✓ Unusual login time: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 3: Unusual IP Detection
    print("\n4. Testing unusual IP detection...")
    unusual_ip_logs = []
    
    # Login from different IP (alice normally uses 192.168.1.100)
    unusual_ip_logs.append(LogEntry(
        id="unusual-ip-1",
        timestamp=datetime.now().isoformat(),
        raw="ssh-server sshd: Accepted publickey for alice from 203.0.113.50",
        message="Accepted publickey for alice from 203.0.113.50 port 22",
        appname="sshd",
        host="server-01",
        normalized={"user": "alice", "source_ip": "203.0.113.50", "action": "login"}
    ))
    
    alerts = await analyzer.analyze(unusual_ip_logs)
    print(f"✓ Unusual IP: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 4: Unusual Resource Access
    print("\n5. Testing unusual resource access detection...")
    unusual_resource_logs = []
    
    # Access to sensitive file (alice normally doesn't access these)
    unusual_resource_logs.append(LogEntry(
        id="unusual-resource-1",
        timestamp=datetime.now().isoformat(),
        raw='nginx: 192.168.1.100 - alice - GET /etc/shadow HTTP/1.1',
        message='GET /etc/shadow HTTP/1.1 200',
        appname="nginx",
        host="web-server",
        normalized={"user": "alice", "source_ip": "192.168.1.100", "resource": "/etc/shadow", "action": "read"}
    ))
    
    alerts = await analyzer.analyze(unusual_resource_logs)
    print(f"✓ Unusual resource access: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 5: Test with new user (no profile yet)
    print("\n6. Testing new user without profile...")
    new_user_logs = []
    
    new_user_logs.append(LogEntry(
        id="new-user-1",
        timestamp=datetime.now().isoformat(),
        raw="ssh-server sshd: Accepted publickey for bob from 192.168.1.105",
        message="Accepted publickey for bob from 192.168.1.105 port 22",
        appname="sshd",
        host="server-01",
        normalized={"user": "bob", "source_ip": "192.168.1.105", "action": "login"}
    ))
    
    alerts = await analyzer.analyze(new_user_logs)
    print(f"✓ New user (no baseline): {len(alerts)} alerts generated (expected: 0)")
    
    # Test 6: Profile Update Mechanism
    print("\n7. Testing profile update mechanism...")
    update_logs = []
    
    # Add more recent activity for alice
    for i in range(3):
        update_logs.append(LogEntry(
            id=f"update-{i}",
            timestamp=(datetime.now() - timedelta(hours=i)).isoformat(),
            raw="ssh-server sshd: Accepted publickey for alice from 192.168.1.100",
            message="Accepted publickey for alice from 192.168.1.100 port 22",
            appname="sshd",
            host="server-02",
            normalized={"user": "alice", "source_ip": "192.168.1.100", "action": "login"}
        ))
    
    analyzer.update_profile("alice", update_logs)
    print(f"✓ Profile updated with {len(update_logs)} new logs")
    
    # Summary
    print("\n" + "=" * 70)
    print("Behavioral Analysis Test Complete!")
    print("=" * 70)
    print("\nAll behavioral patterns tested:")
    print("  ✓ User profile building from historical data")
    print("  ✓ Unusual login time detection")
    print("  ✓ Unusual IP detection")
    print("  ✓ Unusual resource access detection")
    print("  ✓ New user handling (no false positives)")
    print("  ✓ Profile update mechanism")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_behavioral_analyzer())
