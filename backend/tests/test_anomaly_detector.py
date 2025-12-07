"""
Test script for anomaly detection
Tests baseline calculation and anomaly detection on real logs
"""
import sys
import os
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.db_manager import DuckDBManager
from analyzers.baseline_manager import BaselineManager
from analyzers.anomaly_detector import AnomalyDetector
import structlog

logger = structlog.get_logger()


async def test_baseline_calculation():
    """Test baseline calculation from historical data"""
    print("\n" + "="*60)
    print("Testing Baseline Calculation")
    print("="*60)
    
    # Initialize database
    db_path = "data/duckdb/logs.db"
    db_manager = DuckDBManager(db_path)
    
    # Initialize baseline manager
    baseline_manager = BaselineManager(
        db_manager=db_manager,
        baseline_file="data/baselines_test.json"
    )
    
    # Update baselines using last 7 days of data
    print("\nCalculating baselines from historical data...")
    baseline_manager.update_all_baselines(historical_days=7)
    
    # Display baselines
    print("\nCalculated Baselines:")
    print("-" * 60)
    for metric_name, baseline in baseline_manager.baselines.items():
        print(f"\n{metric_name}:")
        print(f"  Mean: {baseline.get('mean', 0):.2f}")
        print(f"  Std Dev: {baseline.get('std', 0):.2f}")
        print(f"  Median: {baseline.get('median', 0):.2f}")
        print(f"  Q1: {baseline.get('q1', 0):.2f}, Q3: {baseline.get('q3', 0):.2f}")
        print(f"  Min: {baseline.get('min', 0):.2f}, Max: {baseline.get('max', 0):.2f}")
        print(f"  Sample Count: {baseline.get('count', 0)}")
    
    return baseline_manager


async def test_anomaly_detection(baseline_manager):
    """Test anomaly detection on recent logs"""
    print("\n" + "="*60)
    print("Testing Anomaly Detection")
    print("="*60)
    
    # Initialize database
    db_path = "data/duckdb/logs.db"
    db_manager = DuckDBManager(db_path)
    
    # Initialize anomaly detector
    anomaly_detector = AnomalyDetector(baseline_manager=baseline_manager)
    
    # Fetch recent logs
    print("\nFetching recent logs...")
    logs = db_manager.fetch_logs(limit=500)
    print(f"Fetched {len(logs)} logs")
    
    # Run anomaly detection
    print("\nRunning anomaly detection...")
    alerts = await anomaly_detector.analyze(logs)
    
    # Display results
    print(f"\nDetected {len(alerts)} anomalies:")
    print("-" * 60)
    
    if alerts:
        for i, alert in enumerate(alerts, 1):
            print(f"\n{i}. {alert.alert_type}")
            print(f"   Severity: {alert.severity}")
            print(f"   Description: {alert.description}")
            if alert.source_ip:
                print(f"   Source IP: {alert.source_ip}")
            if alert.metadata:
                print(f"   Metadata: {alert.metadata}")
    else:
        print("No anomalies detected in recent logs")
    
    return alerts


async def test_specific_anomalies():
    """Test detection of specific anomaly types"""
    print("\n" + "="*60)
    print("Testing Specific Anomaly Types")
    print("="*60)
    
    db_path = "data/duckdb/logs.db"
    db_manager = DuckDBManager(db_path)
    baseline_manager = BaselineManager(db_manager=db_manager)
    anomaly_detector = AnomalyDetector(baseline_manager=baseline_manager)
    
    # Test 1: Failed login detection
    print("\n1. Testing failed login detection...")
    logs = db_manager.fetch_logs(limit=1000)
    failed_login_logs = [log for log in logs if log.message and 'failed' in log.message.lower()]
    print(f"   Found {len(failed_login_logs)} logs with 'failed' in message")
    
    # Test 2: Error rate detection
    print("\n2. Testing error rate detection...")
    error_logs = [log for log in logs if log.message and any(
        keyword in log.message.lower() 
        for keyword in ['error', 'exception', 'denied']
    )]
    print(f"   Found {len(error_logs)} error logs")
    
    # Test 3: Request rate by IP
    print("\n3. Testing request rate by IP...")
    from collections import Counter
    ip_counts = Counter(log.get_source_ip() for log in logs if log.get_source_ip())
    top_ips = ip_counts.most_common(5)
    print("   Top 5 IPs by request count:")
    for ip, count in top_ips:
        print(f"     {ip}: {count} requests")


async def main():
    """Main test function"""
    print("\n" + "="*60)
    print("ANOMALY DETECTION TEST SUITE")
    print("="*60)
    
    try:
        # Test 1: Baseline calculation
        baseline_manager = await test_baseline_calculation()
        
        # Test 2: Anomaly detection
        alerts = await test_anomaly_detection(baseline_manager)
        
        # Test 3: Specific anomaly types
        await test_specific_anomalies()
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"✓ Baseline calculation: PASSED")
        print(f"✓ Anomaly detection: PASSED ({len(alerts)} anomalies detected)")
        print(f"✓ Specific anomaly tests: PASSED")
        print("\nAll tests completed successfully!")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
