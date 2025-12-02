"""
Test script for database connection and data retrieval
"""
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.db_manager import DuckDBManager
from core.config import config
import structlog

logger = structlog.get_logger()


def test_database_connection():
    """Test database connection and basic operations"""
    
    print("=" * 60)
    print("Testing Database Connection")
    print("=" * 60)
    
    # Get database path from config
    db_path = config.get_database_path()
    print(f"\nDatabase path: {db_path}")
    
    # Initialize database manager
    print("\n1. Initializing database manager...")
    try:
        db_manager = DuckDBManager(db_path)
        print("✓ Database manager initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize database manager: {e}")
        return
    
    # Test counting logs
    print("\n2. Counting total logs...")
    try:
        total_logs = db_manager.count_logs()
        print(f"✓ Total logs in database: {total_logs}")
    except Exception as e:
        print(f"✗ Failed to count logs: {e}")
    
    # Test fetching recent logs
    print("\n3. Fetching recent logs (last 5 minutes)...")
    try:
        recent_logs = db_manager.fetch_recent_logs(minutes=5)
        print(f"✓ Fetched {len(recent_logs)} logs from last 5 minutes")
        
        if recent_logs:
            print("\nSample log entry:")
            log = recent_logs[0]
            print(f"  ID: {log.id}")
            print(f"  Timestamp: {log.timestamp}")
            print(f"  Host: {log.host}")
            print(f"  Appname: {log.appname}")
            print(f"  Message: {log.message[:100] if log.message else 'N/A'}...")
            print(f"  Source IP: {log.get_source_ip()}")
            print(f"  User: {log.get_user()}")
    except Exception as e:
        print(f"✗ Failed to fetch recent logs: {e}")
    
    # Test fetching logs with filters
    print("\n4. Testing filtered queries...")
    try:
        # Get unique appnames
        result = db_manager.execute_query(
            "SELECT DISTINCT appname FROM logs LIMIT 5"
        )
        appnames = [row[0] for row in result if row[0]]
        
        if appnames:
            print(f"✓ Found appnames: {', '.join(appnames)}")
            
            # Fetch logs for first appname
            filtered_logs = db_manager.fetch_logs(
                filters={'appname': appnames[0]},
                limit=10
            )
            print(f"✓ Fetched {len(filtered_logs)} logs for appname '{appnames[0]}'")
    except Exception as e:
        print(f"✗ Failed to execute filtered query: {e}")
    
    # Test alert storage
    print("\n5. Testing alert storage...")
    try:
        from storage.models import Alert, Severity
        from datetime import datetime
        import uuid
        
        test_alert = Alert(
            id=str(uuid.uuid4()),
            alert_type="test_alert",
            detection_method="test",
            severity=Severity.INFO,
            description="Test alert from database connection test",
            created_at=datetime.now()
        )
        
        db_manager.store_alert(test_alert)
        print("✓ Test alert stored successfully")
        
        # Fetch the alert back
        alerts = db_manager.fetch_alerts(limit=1)
        if alerts:
            print(f"✓ Fetched alert: {alerts[0].description}")
    except Exception as e:
        print(f"✗ Failed to test alert storage: {e}")
    
    # Close connection
    print("\n6. Closing database connection...")
    db_manager.close()
    print("✓ Connection closed")
    
    print("\n" + "=" * 60)
    print("Database connection test completed!")
    print("=" * 60)


if __name__ == "__main__":
    test_database_connection()
