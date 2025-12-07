"""
Test script for analysis orchestrator
"""
import sys
import asyncio
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzers.orchestrator import AnalysisOrchestrator
from storage.db_manager import DuckDBManager
from core.config import config
import structlog

logger = structlog.get_logger()


async def test_orchestrator():
    """Test the analysis orchestrator"""
    
    print("=" * 70)
    print("Testing Analysis Orchestrator")
    print("=" * 70)
    
    # Initialize database
    print("\n1. Initializing database...")
    db_path = config.get_database_path()
    db_manager = DuckDBManager(db_path)
    print(f"✓ Database initialized: {db_path}")
    
    # Count existing logs
    log_count = db_manager.count_logs()
    print(f"✓ Total logs in database: {log_count}")
    
    # Initialize orchestrator
    print("\n2. Initializing orchestrator...")
    orchestrator_config = {
        'analysis_interval': 60,
        'batch_size': 10000,
        'signature_dir': 'config/signatures',
        'blocked_ips_file': 'config/blocked_ips.txt'
    }
    
    orchestrator = AnalysisOrchestrator(db_manager, orchestrator_config)
    print(f"✓ Orchestrator initialized with {len(orchestrator.detectors)} detectors")
    
    # Run one analysis cycle
    print("\n3. Running analysis cycle...")
    stats = await orchestrator.run_analysis_cycle()
    
    print(f"\n✓ Analysis cycle completed:")
    print(f"  - Logs processed: {stats['logs_processed']}")
    print(f"  - Alerts generated: {stats['alerts_generated']}")
    print(f"  - Cycle time: {stats['cycle_time']:.2f}s")
    
    # Get metrics
    print("\n4. Orchestrator metrics:")
    metrics = orchestrator.get_metrics()
    for key, value in metrics.items():
        print(f"  - {key}: {value}")
    
    # Fetch recent alerts
    print("\n5. Recent alerts:")
    alerts = db_manager.fetch_alerts(limit=10)
    
    if not alerts:
        print("  No alerts found")
    else:
        print(f"  Found {len(alerts)} recent alerts:")
        for i, alert in enumerate(alerts[:5], 1):
            print(f"\n  Alert #{i}:")
            print(f"    Type: {alert.alert_type}")
            print(f"    Severity: {alert.severity}")
            print(f"    Description: {alert.description}")
            print(f"    Host: {alert.host}")
            print(f"    Created: {alert.created_at}")
    
    # Test continuous mode (run for 30 seconds)
    print("\n6. Testing continuous mode (30 seconds)...")
    print("  Starting orchestrator...")
    
    # Run in background
    task = asyncio.create_task(orchestrator.start(interval=10))
    
    # Wait 30 seconds
    await asyncio.sleep(60)
    
    # Stop orchestrator
    orchestrator.stop()
    
    # Wait for task to complete
    try:
        await asyncio.wait_for(task, timeout=5)
    except asyncio.TimeoutError:
        task.cancel()
    
    print("\n  ✓ Continuous mode test completed")
    
    # Final metrics
    print("\n7. Final metrics:")
    final_metrics = orchestrator.get_metrics()
    for key, value in final_metrics.items():
        print(f"  - {key}: {value}")
    
    # Close database
    db_manager.close()
    
    print("\n" + "=" * 70)
    print("Orchestrator Test Complete!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_orchestrator())
