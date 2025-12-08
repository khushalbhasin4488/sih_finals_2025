"""
Analytics Engine
Calculates aggregated metrics for comprehensive log analysis

Categories:
1. Volume & Traffic Patterns
2. Performance & Latency
3. Errors & Reliability
4. Security & Access
5. User Behavior
6. Infrastructure
"""
import duckdb
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import structlog

from storage.db_manager import DuckDBManager

logger = structlog.get_logger()


class AnalyticsEngine:
    """
    Engine for calculating log analytics and metrics
    Uses DuckDB for efficient aggregation of large datasets
    """
    
    def __init__(self, db_manager: DuckDBManager):
        self.db_manager = db_manager
    
    def get_overview_stats(self, time_range_minutes: int = 1440, network_id: str = None) -> Dict[str, Any]:
        """
        Get high-level overview statistics for the unified dashboard
        
        Args:
            time_range_minutes: Time range in minutes (default 24h)
            network_id: Optional network ID to filter by
        """
        start_time = datetime.now() - timedelta(minutes=time_range_minutes)
        
        stats = {
            "volume": self._get_volume_stats(start_time, network_id),
            "performance": self._get_performance_stats(start_time, network_id),
            "errors": self._get_error_stats(start_time, network_id),
            "security": self._get_security_stats(start_time, network_id),
            "users": self._get_user_stats(start_time, network_id)
        }
        
        return stats

    def _get_volume_stats(self, start_time: datetime, network_id: str = None) -> Dict[str, Any]:
        """1. Volume & Traffic Patterns"""
        with self.db_manager.get_connection() as conn:
            # Build network filter
            network_filter = "AND network_id = ?" if network_id else ""
            params = [start_time, network_id] if network_id else [start_time]
            # Total requests
            total_reqs = conn.execute(
                f"SELECT COUNT(*) FROM logs WHERE ingestion_time >= ? {network_filter}", 
                params
            ).fetchone()[0]
            
            # Request rate (per minute)
            minutes = (datetime.now() - start_time).total_seconds() / 60
            req_rate = round(total_reqs / minutes, 2) if minutes > 0 else 0
            
            # Peak load time (hour of day)
            peak_hour = conn.execute(f"""
                SELECT strftime(ingestion_time, '%H') as hour, COUNT(*) as count
                FROM logs 
                WHERE ingestion_time >= ? {network_filter}
                GROUP BY hour
                ORDER BY count DESC
                LIMIT 1
            """, params).fetchone()
            
            peak_time = f"{peak_hour[0]}:00" if peak_hour else "N/A"
            
            # Active endpoints
            endpoints = conn.execute(f"""
                SELECT 
                    json_extract_string(normalized, '$.method') || ' ' || 
                    json_extract_string(normalized, '$.path') as endpoint,
                    COUNT(*) as count
                FROM logs 
                WHERE ingestion_time >= ? {network_filter}
                AND json_extract_string(normalized, '$.path') IS NOT NULL
                GROUP BY endpoint
                ORDER BY count DESC
                LIMIT 5
            """, params).fetchall()
            
            return {
                "total_requests": total_reqs,
                "requests_per_minute": req_rate,
                "peak_load_time": peak_time,
                "top_endpoints": [{"endpoint": e[0], "count": e[1]} for e in endpoints]
            }

    def _get_performance_stats(self, start_time: datetime, network_id: str = None) -> Dict[str, Any]:
        """2. Performance & Latency"""
        with self.db_manager.get_connection() as conn:
            network_filter = "AND network_id = ?" if network_id else ""
            params = [start_time, network_id] if network_id else [start_time]
            # Stats from 'response_time_ms' in normalized or parsed from message
            # For now assuming it's in normalized JSON or null
            perf_data = conn.execute(f"""
                SELECT 
                    AVG(CAST(json_extract_string(normalized, '$.response_time_ms') AS FLOAT)) as avg_latency,
                    quantile_cont(CAST(json_extract_string(normalized, '$.response_time_ms') AS FLOAT), 0.99) as p99_latency,
                    SUM(CAST(json_extract_string(normalized, '$.response_bytes') AS INTEGER)) as total_bytes
                FROM logs 
                WHERE ingestion_time >= ? {network_filter}
                AND json_extract_string(normalized, '$.response_time_ms') IS NOT NULL
            """, params).fetchone()
            
            # Slowest endpoints
            slow_queries = conn.execute(f"""
                SELECT 
                    json_extract_string(normalized, '$.path') as path,
                    AVG(CAST(json_extract_string(normalized, '$.response_time_ms') AS FLOAT)) as avg_time
                FROM logs
                WHERE ingestion_time >= ? {network_filter}
                AND json_extract_string(normalized, '$.response_time_ms') IS NOT NULL
                GROUP BY path
                ORDER BY avg_time DESC
                LIMIT 3
            """, params).fetchall()
            
            return {
                "avg_response_time": round(perf_data[0] or 0, 2),
                "p99_response_time": round(perf_data[1] or 0, 2),
                "total_bandwidth_bytes": perf_data[2] or 0,
                "slowest_endpoints": [{"path": s[0], "avg_time": round(s[1], 2)} for s in slow_queries]
            }

    def _get_error_stats(self, start_time: datetime, network_id: str = None) -> Dict[str, Any]:
        """3. Errors & Reliability"""
        with self.db_manager.get_connection() as conn:
            network_filter = "AND network_id = ?" if network_id else ""
            params = [start_time, network_id] if network_id else [start_time]
            # Status code distribution
            status_codes = conn.execute(f"""
                SELECT 
                    json_extract_string(normalized, '$.status_code') as status,
                    COUNT(*) as count
                FROM logs
                WHERE ingestion_time >= ? {network_filter}
                AND json_extract_string(normalized, '$.status_code') IS NOT NULL
                GROUP BY status
            """, params).fetchall()
            
            # Top error messages
            errors = conn.execute(f"""
                SELECT message, COUNT(*) as count
                FROM logs
                WHERE ingestion_time >= ? {network_filter}
                AND (
                    message ILIKE '%error%' 
                    OR message ILIKE '%fail%' 
                    OR message ILIKE '%exception%'
                )
                GROUP BY message
                ORDER BY count DESC
                LIMIT 5
            """, params).fetchall()
            
            return {
                "status_distribution": [{"status": s[0], "count": s[1]} for s in status_codes],
                "top_errors": [{"message": e[0][:50] + "...", "count": e[1]} for e in errors]
            }

    def _get_security_stats(self, start_time: datetime, network_id: str = None) -> Dict[str, Any]:
        """4. Security & Access"""
        with self.db_manager.get_connection() as conn:
            network_filter = "AND network_id = ?" if network_id else ""
            params = [start_time, network_id] if network_id else [start_time]
            # Failed logins
            failed_logins = conn.execute(f"""
                SELECT COUNT(*)
                FROM logs
                WHERE ingestion_time >= ? {network_filter}
                AND (
                    message ILIKE '%failed login%' 
                    OR message ILIKE '%authentication failure%'
                    OR json_extract_string(normalized, '$.event_type') = 'failed_login'
                )
            """, params).fetchone()[0]
            
            # Top source IPs (Potential attackers or busy users)
            top_ips = conn.execute(f"""
                SELECT 
                    COALESCE(
                        json_extract_string(normalized, '$.source_ip'), 
                        NULLIF(regexp_extract(message, 'SRC=([0-9.]+)', 1), '')
                    ) as ip,
                    COUNT(*) as count
                FROM logs
                WHERE ingestion_time >= ? {network_filter}
                GROUP BY ip
                HAVING ip IS NOT NULL
                ORDER BY count DESC
                LIMIT 5
            """, params).fetchall()
            
            return {
                "failed_logins": failed_logins,
                "top_source_ips": [{"ip": i[0], "count": i[1]} for i in top_ips]
            }

    def _get_user_stats(self, start_time: datetime, network_id: str = None) -> Dict[str, Any]:
        """5. User Behavior"""
        with self.db_manager.get_connection() as conn:
            network_filter = "AND network_id = ?" if network_id else ""
            params = [start_time, network_id] if network_id else [start_time]
            # Unique users (if available)
            unique_users = conn.execute(f"""
                SELECT COUNT(DISTINCT 
                    COALESCE(
                        json_extract_string(normalized, '$.user'),
                        NULLIF(regexp_extract(message, 'user[= ]([a-zA-Z0-9_]+)', 1), '')
                    )
                )
                FROM logs
                WHERE ingestion_time >= ? {network_filter}
            """, params).fetchone()[0]
            
            # User agents breakdown
            user_agents = conn.execute(f"""
                SELECT 
                    json_extract_string(normalized, '$.user_agent') as ua,
                    COUNT(*) as count
                FROM logs
                WHERE ingestion_time >= ? {network_filter}
                AND ua IS NOT NULL
                GROUP BY ua
                ORDER BY count DESC
                LIMIT 5
            """, params).fetchall()
            
            return {
                "unique_active_users": unique_users,
                "top_user_agents": [{"agent": u[0][:30], "count": u[1]} for u in user_agents]
            }
