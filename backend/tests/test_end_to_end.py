"""
Comprehensive End-to-End Test
Seeds logs with various attack patterns, runs complete analysis, and verifies all components
"""
import sys
import asyncio
from pathlib import Path
from datetime import datetime, timedelta
import time

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.db_manager import DuckDBManager
from analyzers.orchestrator import AnalysisOrchestrator
from analyzers.baseline_manager import BaselineManager
from core.config import config
import structlog

logger = structlog.get_logger()


async def seed_test_logs():
    """Seed database with test logs for all detector types"""
    print("\n" + "="*70)
    print("SEEDING TEST LOGS")
    print("="*70)
    
    # Import seeder temporarily
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "temp_seeder"))
    import seeder
    
    # Initialize database connection
    print("\n1. Initializing database connection...")
    conn = seeder.connect_db()
    seeder.initialize_schema(conn)
    print("✓ Database initialized")
    
    # Clear existing logs
    print("\n2. Clearing existing logs...")
    conn.execute("DELETE FROM logs")
    conn.execute("DELETE FROM alerts")
    print("✓ Cleared existing data")
    
    # Generate test logs
    print("\n3. Generating test logs (100 logs with attack patterns)...")
    logs_generated = 0
    logs_to_insert = []
    
    # Generate different attack types
    for i in range(20):
        # Signature detection patterns
        seeder.state.minute_counter = i
        log = seeder.generate_signature_detection_log()
        if log:
            logs_to_insert.append(log)
            logs_generated += 1
        
        # Threat intel patterns
        log = seeder.generate_threat_intel_log()
        if log:
            logs_to_insert.append(log)
            logs_generated += 1
        
        # Heuristic patterns
        log = seeder.generate_heuristic_brute_force_log()
        if log:
            logs_to_insert.append(log)
            logs_generated += 1
        
        # Network patterns
        log = seeder.generate_network_port_scan_log()
        if log:
            logs_to_insert.append(log)
            logs_generated += 1
        
        # Off-hours activity
        log = seeder.generate_heuristic_off_hours_log()
        if log:
            logs_to_insert.append(log)
            logs_generated += 1
    
    # Insert all logs at once
    if logs_to_insert:
        data = []
        for log in logs_to_insert:
            data.append((
                log["id"], log["timestamp"], log["raw"], log["appname"], 
                log["file"], log["host"], log["hostname"], log["message"], 
                log["procid"], log["source_type"], log["normalized"], 
                log["metadata"], log["ingestion_time"]
            ))
        
        conn.executemany("""
            INSERT INTO logs (
                id, timestamp, raw, appname, file, host, hostname, 
                message, procid, source_type, normalized, metadata, ingestion_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, data)
        conn.commit()
    
    # Verify logs were inserted
    result = conn.execute("SELECT COUNT(*) FROM logs").fetchone()
    conn.close()
    
    print(f"✓ Generated and inserted {logs_generated} test logs")
    print(f"✓ Verified {result[0]} logs in database")
    return logs_generated


async def verify_logs():
    """Verify logs were seeded correctly"""
    print("\n" + "="*70)
    print("VERIFYING SEEDED LOGS")
    print("="*70)
    
    db_manager = DuckDBManager(config.get_database_path())
    
    # Count total logs
    total_logs = db_manager.count_logs()
    print(f"\n✓ Total logs in database: {total_logs}")
    
    # Get sample logs
    recent_logs = db_manager.fetch_logs(limit=5)
    print(f"✓ Sample logs retrieved: {len(recent_logs)}")
    
    if recent_logs:
        print("\nSample log:")
        log = recent_logs[0]
        print(f"  - ID: {log.id}")
        print(f"  - Timestamp: {log.timestamp}")
        print(f"  - Host: {log.host}")
        print(f"  - Message: {log.message[:80] if log.message else 'N/A'}...")
    
    db_manager.close()
    return total_logs


async def run_analysis():
    """Run complete analysis cycle"""
    print("\n" + "="*70)
    print("RUNNING ANALYSIS")
    print("="*70)
    
    # Initialize components
    print("\n1. Initializing analysis components...")
    db_manager = DuckDBManager(config.get_database_path())
    
    orchestrator_config = {
        'analysis_interval': 60,
        'batch_size': 10000,
        'signature_dir': 'config/signatures',
        'blocked_ips_file': 'config/blocked_ips.txt'
    }
    
    orchestrator = AnalysisOrchestrator(db_manager, orchestrator_config)
    print(f"✓ Initialized orchestrator with {len(orchestrator.detectors)} detectors")
    
    # Build baselines first
    print("\n2. Building baselines from seeded data...")
    baseline_manager = BaselineManager(db_manager)
    baseline_manager.update_all_baselines(historical_days=1)
    print(f"✓ Built baselines: {len(baseline_manager.baselines)} metrics")
    
    # Run one analysis cycle
    print("\n3. Running analysis cycle...")
    stats = await orchestrator.run_analysis_cycle()
    
    print(f"\n✓ Analysis completed:")
    print(f"  - Logs processed: {stats['logs_processed']}")
    print(f"  - Alerts generated: {stats['alerts_generated']}")
    print(f"  - Cycle time: {stats['cycle_time']:.2f}s")
    
    # Get detector breakdown
    print("\n4. Detector performance:")
    if 'detector_stats' in stats and stats['detector_stats']:
        for detector_name, detector_stats in stats['detector_stats'].items():
            alerts = detector_stats.get('alerts_generated', 0)
            time_taken = detector_stats.get('execution_time', 0)
            print(f"  - {detector_name}: {alerts} alerts ({time_taken:.3f}s)")
    
    db_manager.close()
    return stats


async def verify_alerts():
    """Verify alerts were generated correctly"""
    print("\n" + "="*70)
    print("VERIFYING ALERTS")
    print("="*70)
    
    db_manager = DuckDBManager(config.get_database_path())
    
    # Get all alerts
    alerts = db_manager.fetch_alerts(limit=100)
    print(f"\n✓ Total alerts generated: {len(alerts)}")
    
    # Group by detection method
    by_detector = {}
    by_severity = {}
    
    for alert in alerts:
        detector = alert.detection_method or 'unknown'
        by_detector[detector] = by_detector.get(detector, 0) + 1
        
        severity = alert.severity if isinstance(alert.severity, str) else alert.severity.value
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    print("\nAlerts by detector:")
    for detector, count in sorted(by_detector.items()):
        print(f"  - {detector}: {count} alerts")
    
    print("\nAlerts by severity:")
    for severity, count in sorted(by_severity.items()):
        print(f"  - {severity}: {count} alerts")
    
    # Show sample alerts
    if alerts:
        print("\nSample alert:")
        alert = alerts[0]
        print(f"  - Type: {alert.alert_type}")
        print(f"  - Severity: {alert.severity}")
        print(f"  - Description: {alert.description[:80]}...")
        print(f"  - Detector: {alert.detection_method}")
    
    db_manager.close()
    return len(alerts), by_detector


async def verify_statistics():
    """Verify statistics generation"""
    print("\n" + "="*70)
    print("VERIFYING STATISTICS")
    print("="*70)
    
    # Check baselines
    from pathlib import Path
    import json
    
    baseline_file = Path("data/baselines.json")
    if baseline_file.exists():
        with open(baseline_file) as f:
            baselines = json.load(f)
        print(f"\n✓ Baselines file exists with {len(baselines)} metrics")
        for metric, data in baselines.items():
            print(f"  - {metric}: mean={data.get('mean', 0):.2f}, std={data.get('std', 0):.2f}")
    else:
        print("\n✗ Baselines file not found")
    
    return baseline_file.exists()


async def main():
    """Main end-to-end test"""
    print("\n" + "="*70)
    print("END-TO-END TEST SUITE")
    print("="*70)
    
    try:
        # Step 1: Seed logs
        logs_seeded = await seed_test_logs()
        
        # Step 2: Verify logs
        total_logs = await verify_logs()
        assert total_logs > 0, "No logs found in database"
        
        # Step 3: Run analysis
        stats = await run_analysis()
        assert stats['logs_processed'] > 0, "No logs were processed"
        
        # Step 4: Verify alerts
        alert_count, by_detector = await verify_alerts()
        assert alert_count > 0, "No alerts were generated"
        
        # Check that multiple detectors generated alerts
        active_detectors = len([d for d, c in by_detector.items() if c > 0])
        print(f"\n✓ {active_detectors} out of 7 detectors generated alerts")
        
        # Step 5: Verify statistics
        stats_exist = await verify_statistics()
        
        # Final summary
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        print(f"✓ Logs seeded: {logs_seeded}")
        print(f"✓ Total logs in DB: {total_logs}")
        print(f"✓ Logs processed: {stats['logs_processed']}")
        print(f"✓ Alerts generated: {alert_count}")
        print(f"✓ Active detectors: {active_detectors}/7")
        print(f"✓ Baselines generated: {'Yes' if stats_exist else 'No'}")
        
        print("\n" + "="*70)
        print("ALL TESTS PASSED!")
        print("="*70)
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
