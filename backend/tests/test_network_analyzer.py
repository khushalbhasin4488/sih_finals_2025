"""
Test script for network traffic analysis
Tests port scanning, DDoS, beaconing, and DNS tunneling detection
"""
import sys
import asyncio
from pathlib import Path
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.network_analyzer import NetworkAnalyzer
from storage.models import LogEntry
import structlog

logger = structlog.get_logger()


async def test_network_analyzer():
    """Test the network analyzer with sample attack patterns"""
    
    print("=" * 70)
    print("Testing Network Traffic Analysis")
    print("=" * 70)
    
    # Initialize analyzer
    print("\n1. Initializing network analyzer...")
    analyzer = NetworkAnalyzer()
    print(f"✓ Network analyzer initialized")
    
    # Test 1: Port Scanning Detection
    print("\n2. Testing port scan detection...")
    port_scan_logs = []
    base_time = datetime.now()
    
    # Scan 15 different ports from same IP
    for port in [22, 23, 80, 443, 3389, 445, 21, 25, 110, 143, 3306, 5432, 6379, 27017, 8080]:
        port_scan_logs.append(LogEntry(
            id=f"ps-{port}",
            timestamp=(base_time + timedelta(milliseconds=port)).isoformat(),
            raw=f"2024-12-08 02:10:00 firewall UFW BLOCK: SRC=45.142.212.61 DST=192.168.1.1 DPT={port}",
            message=f"UFW BLOCK: SRC=45.142.212.61 DST=192.168.1.1 PROTO=TCP DPT={port}",
            appname="kernel",
            host="firewall",
            normalized={"source_ip": "45.142.212.61", "dest_ip": "192.168.1.1", "dest_port": port, "protocol": "tcp"}
        ))
    
    alerts = await analyzer.analyze(port_scan_logs)
    print(f"✓ Port scan detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 2: DDoS Detection
    print("\n3. Testing DDoS detection...")
    ddos_logs = []
    
    # 100 requests to same target from different IPs
    for i in range(100):
        ddos_logs.append(LogEntry(
            id=f"ddos-{i}",
            timestamp=(base_time + timedelta(milliseconds=i*10)).isoformat(),
            raw=f"2024-12-08 02:15:00 web-server nginx: 10.0.{i//256}.{i%256} - - GET / HTTP/1.1",
            message=f"GET / HTTP/1.1 200",
            appname="nginx",
            host="web-server",
            normalized={"source_ip": f"10.0.{i//256}.{i%256}", "dest_ip": "192.168.1.100", "dest_port": 80}
        ))
    
    alerts = await analyzer.analyze(ddos_logs)
    print(f"✓ DDoS detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 3: Beaconing Detection (C2)
    print("\n4. Testing beaconing detection...")
    beaconing_logs = []
    
    # Regular periodic connections (every 60 seconds)
    for i in range(10):
        beaconing_logs.append(LogEntry(
            id=f"beacon-{i}",
            timestamp=(base_time + timedelta(seconds=i*60)).isoformat(),
            raw=f"2024-12-08 02:20:{i:02d} server-01 nginx: 192.168.1.50 - - GET /check HTTP/1.1",
            message="GET /check HTTP/1.1 200 45",
            appname="nginx",
            host="server-01",
            normalized={"source_ip": "192.168.1.50", "dest_ip": "45.142.212.61", "dest_port": 8443, "bytes": 45}
        ))
    
    alerts = await analyzer.analyze(beaconing_logs)
    print(f"✓ Beaconing detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 4: DNS Tunneling Detection
    print("\n5. Testing DNS tunneling detection...")
    dns_logs = []
    
    # Excessive DNS queries (50 in short period)
    for i in range(50):
        dns_logs.append(LogEntry(
            id=f"dns-{i}",
            timestamp=(base_time + timedelta(seconds=i)).isoformat(),
            raw=f"2024-12-08 02:25:{i:02d} dns-server bind: Query: data{i:04d}.evil.com from 192.168.1.75",
            message=f"DNS query for data{i:04d}.evil.com",
            appname="bind",
            host="dns-server",
            normalized={"source_ip": "192.168.1.75", "protocol": "dns", "domain": f"data{i:04d}.evil.com"}
        ))
    
    alerts = await analyzer.analyze(dns_logs)
    print(f"✓ DNS tunneling detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Test 5: Protocol Anomalies
    print("\n6. Testing protocol anomaly detection...")
    protocol_logs = []
    
    # HTTP on unusual port
    protocol_logs.append(LogEntry(
        id="proto-1",
        timestamp=base_time.isoformat(),
        raw="2024-12-08 02:30:00 firewall: Connection to 192.168.1.100:4444",
        message="Connection to 192.168.1.100:4444",
        appname="kernel",
        host="firewall",
        normalized={"dest_ip": "192.168.1.100", "dest_port": 4444, "protocol": "tcp"}
    ))
    
    alerts = await analyzer.analyze(protocol_logs)
    print(f"✓ Protocol anomaly detection: {len(alerts)} alerts generated")
    if alerts:
        for alert in alerts:
            print(f"  - {alert.description[:80]}...")
    
    # Summary
    print("\n" + "=" * 70)
    print("Network Traffic Analysis Test Complete!")
    print("=" * 70)
    print("\nAll network patterns tested:")
    print("  ✓ Port scanning (15 ports)")
    print("  ✓  DDoS attack (100 requests)")
    print("  ✓ C2 beaconing (periodic connections)")
    print("  ✓ DNS tunneling (50 queries)")
    print("  ✓ Protocol anomalies")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_network_analyzer())
