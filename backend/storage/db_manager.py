"""
DuckDB Database Manager
Handles connection, queries, and data retrieval from DuckDB
"""
import duckdb
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
import structlog
from contextlib import contextmanager

from .models import LogEntry, Alert, ThreatIntel, DetectionRule

logger = structlog.get_logger()


class DuckDBManager:
    """
    Manages DuckDB connections and operations
    Handles flexible schema for logs from different services
    """
    
    def __init__(self, db_path: str):
        """
        Initialize DuckDB manager
        
        Args:
            db_path: Path to DuckDB database file
        """
        self.db_path = db_path
        self.connection = None  # No persistent connection
        
        # Ensure database directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize schema using temporary connection
        with self.get_connection() as conn:
            self._initialize_schema_with_conn(conn)
        
        logger.info("DuckDB manager initialized", db_path=db_path)
    
    def _connect(self):
        """Establish connection to DuckDB (deprecated - use get_connection instead)"""
        try:
            return duckdb.connect(self.db_path)
        except Exception as e:
            logger.error("Failed to connect to DuckDB", error=str(e))
            raise
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections
        Opens a new connection for each use to avoid locking issues
        """
        conn = None
        try:
            conn = duckdb.connect(self.db_path)
            yield conn
        except Exception as e:
            logger.error("Database connection error", error=str(e))
            raise
        finally:
            if conn:
                conn.close()
    
    def _initialize_schema_with_conn(self, conn):
        """
        Initialize database schema with provided connection
        Creates tables if they don't exist
        
        Args:
            conn: DuckDB connection object
        """
        # Logs table - flexible schema to handle different log formats
        # Using JSON type for flexible fields
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id VARCHAR PRIMARY KEY,
                timestamp VARCHAR,
                raw VARCHAR,
                appname VARCHAR,
                file VARCHAR,
                host VARCHAR,
                hostname VARCHAR,
                message VARCHAR,
                procid INTEGER,
                source_type VARCHAR,
                normalized JSON,
                metadata JSON,
                ingestion_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for common query patterns
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp 
            ON logs(timestamp)
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_host 
            ON logs(host)
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_appname 
            ON logs(appname)
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_ingestion_time 
            ON logs(ingestion_time)
        """)
        
        # Alerts table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id VARCHAR PRIMARY KEY,
                log_id VARCHAR,
                alert_type VARCHAR,
                detection_method VARCHAR,
                severity VARCHAR,
                description VARCHAR,
                metadata JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged BOOLEAN DEFAULT FALSE,
                priority_score DOUBLE,
                source_ip VARCHAR,
                dest_ip VARCHAR,
                user VARCHAR,
                host VARCHAR
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_created_at 
            ON alerts(created_at)
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity 
            ON alerts(severity)
        """)
        
        # Threat intelligence table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id VARCHAR PRIMARY KEY,
                indicator_type VARCHAR,
                indicator_value VARCHAR,
                threat_type VARCHAR,
                confidence DOUBLE,
                source VARCHAR,
                metadata JSON,
                created_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator 
            ON threat_intel(indicator_type, indicator_value)
        """)
        
        # Detection rules table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                id VARCHAR PRIMARY KEY,
                rule_name VARCHAR,
                rule_type VARCHAR,
                rule_definition JSON,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """)
        
        logger.info("Database schema initialized")
    
    def fetch_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 10000,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[LogEntry]:
        """
        Fetch logs from database with optional filters
        
        Args:
            start_time: Start timestamp for log retrieval
            end_time: End timestamp for log retrieval
            limit: Maximum number of logs to retrieve
            offset: Offset for pagination
            filters: Additional filters (e.g., {'appname': 'sshd', 'host': 'server1'})
        
        Returns:
            List of LogEntry objects
        """
        with self.get_connection() as conn:
            query = "SELECT * FROM logs WHERE 1=1"
            params = []
            
            # Time range filter
            if start_time:
                query += " AND ingestion_time >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND ingestion_time <= ?"
                params.append(end_time)
            
            # Additional filters
            if filters:
                for key, value in filters.items():
                    if key in ['appname', 'host', 'hostname', 'source_type', 'file']:
                        query += f" AND {key} = ?"
                        params.append(value)
            
            # Order by ingestion time (most recent first)
            query += " ORDER BY ingestion_time DESC"
            
            # Pagination
            query += f" LIMIT {limit} OFFSET {offset}"
            
            try:
                result = conn.execute(query, params).fetchall()
                columns = [desc[0] for desc in conn.description]
                
                logs = []
                for row in result:
                    log_dict = dict(zip(columns, row))
                    
                    # Parse JSON fields
                    if log_dict.get('normalized'):
                        log_dict['normalized'] = json.loads(log_dict['normalized']) if isinstance(log_dict['normalized'], str) else log_dict['normalized']
                    
                    if log_dict.get('metadata'):
                        log_dict['metadata'] = json.loads(log_dict['metadata']) if isinstance(log_dict['metadata'], str) else log_dict['metadata']
                    
                    logs.append(LogEntry.from_dict(log_dict))
                
                logger.info("Fetched logs", count=len(logs), start_time=start_time, end_time=end_time)
                return logs
                
            except Exception as e:
                logger.error("Error fetching logs", error=str(e))
                raise
    
    def fetch_recent_logs(self, minutes: int = 1) -> List[LogEntry]:
        """
        Fetch logs from the last N minutes
        
        Args:
            minutes: Number of minutes to look back
        
        Returns:
            List of LogEntry objects
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        return self.fetch_logs(start_time=start_time, end_time=end_time)
    
    def fetch_logs_by_ids(self, log_ids: List[str]) -> List[LogEntry]:
        """
        Fetch specific logs by their IDs
        
        Args:
            log_ids: List of log IDs
        
        Returns:
            List of LogEntry objects
        """
        if not log_ids:
            return []
        
        with self.get_connection() as conn:
            placeholders = ','.join(['?' for _ in log_ids])
            query = f"SELECT * FROM logs WHERE id IN ({placeholders})"
            
            try:
                result = conn.execute(query, log_ids).fetchall()
                columns = [desc[0] for desc in conn.description]
                
                logs = []
                for row in result:
                    log_dict = dict(zip(columns, row))
                    
                    # Parse JSON fields
                    if log_dict.get('normalized'):
                        log_dict['normalized'] = json.loads(log_dict['normalized']) if isinstance(log_dict['normalized'], str) else log_dict['normalized']
                    
                    if log_dict.get('metadata'):
                        log_dict['metadata'] = json.loads(log_dict['metadata']) if isinstance(log_dict['metadata'], str) else log_dict['metadata']
                    
                    logs.append(LogEntry.from_dict(log_dict))
                
                return logs
                
            except Exception as e:
                logger.error("Error fetching logs by IDs", error=str(e))
                raise
    
    def count_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Count logs matching criteria
        
        Args:
            start_time: Start timestamp
            end_time: End timestamp
            filters: Additional filters
        
        Returns:
            Count of matching logs
        """
        with self.get_connection() as conn:
            query = "SELECT COUNT(*) FROM logs WHERE 1=1"
            params = []
            
            if start_time:
                query += " AND ingestion_time >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND ingestion_time <= ?"
                params.append(end_time)
            
            if filters:
                for key, value in filters.items():
                    if key in ['appname', 'host', 'hostname', 'source_type', 'file']:
                        query += f" AND {key} = ?"
                        params.append(value)
            
            try:
                result = conn.execute(query, params).fetchone()
                return result[0] if result else 0
            except Exception as e:
                logger.error("Error counting logs", error=str(e))
                raise
    
    def store_alert(self, alert: Alert) -> bool:
        """
        Store an alert in the database
        
        Args:
            alert: Alert object to store
        
        Returns:
            True if successful
        """
        with self.get_connection() as conn:
            try:
                conn.execute("""
                    INSERT INTO alerts (
                        id, log_id, alert_type, detection_method, severity,
                        description, metadata, created_at, acknowledged,
                        priority_score, source_ip, dest_ip, user, host
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    alert.id,
                    alert.log_id,
                    alert.alert_type,
                    alert.detection_method,
                    alert.severity,
                    alert.description,
                    json.dumps(alert.metadata) if alert.metadata else None,
                    alert.created_at,
                    alert.acknowledged,
                    alert.priority_score,
                    alert.source_ip,
                    alert.dest_ip,
                    alert.user,
                    alert.host
                ])
                
                logger.info("Alert stored", alert_id=alert.id, alert_type=alert.alert_type)
                return True
                
            except Exception as e:
                logger.error("Error storing alert", error=str(e), alert_id=alert.id)
                raise
    
    def store_alerts_batch(self, alerts: List[Alert]) -> int:
        """
        Store multiple alerts in a batch
        
        Args:
            alerts: List of Alert objects
        
        Returns:
            Number of alerts stored
        """
        if not alerts:
            return 0
        
        with self.get_connection() as conn:
            try:
                data = [
                    (
                        alert.id, alert.log_id, alert.alert_type, alert.detection_method,
                        alert.severity, alert.description,
                        json.dumps(alert.metadata) if alert.metadata else None,
                        alert.created_at, alert.acknowledged, alert.priority_score,
                        alert.source_ip, alert.dest_ip, alert.user, alert.host
                    )
                    for alert in alerts
                ]
                
                conn.executemany("""
                    INSERT INTO alerts (
                        id, log_id, alert_type, detection_method, severity,
                        description, metadata, created_at, acknowledged,
                        priority_score, source_ip, dest_ip, user, host
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, data)
                
                logger.info("Alerts stored in batch", count=len(alerts))
                return len(alerts)
                
            except Exception as e:
                logger.error("Error storing alerts batch", error=str(e))
                raise
    
    def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 1000
    ) -> List[Alert]:
        """
        Fetch alerts from database
        
        Args:
            start_time: Start timestamp
            end_time: End timestamp
            severity: Filter by severity
            acknowledged: Filter by acknowledgment status
            limit: Maximum number of alerts
        
        Returns:
            List of Alert objects
        """
        with self.get_connection() as conn:
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if start_time:
                query += " AND created_at >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND created_at <= ?"
                params.append(end_time)
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if acknowledged is not None:
                query += " AND acknowledged = ?"
                params.append(acknowledged)
            
            query += " ORDER BY created_at DESC"
            query += f" LIMIT {limit}"
            
            try:
                result = conn.execute(query, params).fetchall()
                columns = [desc[0] for desc in conn.description]
                
                alerts = []
                for row in result:
                    alert_dict = dict(zip(columns, row))
                    
                    # Parse JSON metadata
                    if alert_dict.get('metadata'):
                        alert_dict['metadata'] = json.loads(alert_dict['metadata']) if isinstance(alert_dict['metadata'], str) else alert_dict['metadata']
                    
                    alerts.append(Alert.from_dict(alert_dict))
                
                return alerts
                
            except Exception as e:
                logger.error("Error fetching alerts", error=str(e))
                raise
    
    def execute_query(self, query: str, params: Optional[List] = None) -> List[Tuple]:
        """
        Execute a custom SQL query
        
        Args:
            query: SQL query string
            params: Query parameters
        
        Returns:
            Query results as list of tuples
        """
        with self.get_connection() as conn:
            try:
                if params:
                    result = conn.execute(query, params).fetchall()
                else:
                    result = conn.execute(query).fetchall()
                
                return result
                
            except Exception as e:
                logger.error("Error executing query", error=str(e), query=query)
                raise
    
    def fetch_threat_intel(
        self,
        indicator_type: Optional[str] = None,
        indicator_value: Optional[str] = None
    ) -> List[ThreatIntel]:
        """
        Fetch threat intelligence indicators
        
        Args:
            indicator_type: Filter by indicator type
            indicator_value: Filter by indicator value
            
        Returns:
            List of ThreatIntel objects
        """
        with self.get_connection() as conn:
            query = "SELECT * FROM threat_intel WHERE 1=1"
            params = []
            
            if indicator_type:
                query += " AND indicator_type = ?"
                params.append(indicator_type)
            
            if indicator_value:
                query += " AND LOWER(indicator_value) = LOWER(?)"
                params.append(indicator_value)
            
            # Only fetch non-expired indicators
            query += " AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
            
            try:
                result = conn.execute(query, params).fetchall()
                columns = [desc[0] for desc in conn.description]
                
                threat_intels = []
                for row in result:
                    ti_dict = dict(zip(columns, row))
                    
                    # Parse JSON metadata
                    if ti_dict.get('metadata'):
                        ti_dict['metadata'] = json.loads(ti_dict['metadata']) if isinstance(ti_dict['metadata'], str) else ti_dict['metadata']
                    
                    threat_intels.append(ThreatIntel.from_dict(ti_dict))
                
                return threat_intels
                
            except Exception as e:
                logger.error("Error fetching threat intel", error=str(e))
                return []
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")
