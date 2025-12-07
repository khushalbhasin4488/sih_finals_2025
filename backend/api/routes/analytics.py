"""
Analytics API endpoints for charts and visualizations
"""
from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta
from typing import Optional
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from storage.db_manager import DuckDBManager
from analyzers.baseline_manager import BaselineManager
from core.config import config
import structlog

logger = structlog.get_logger()
router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/anomalies/timeline")
async def get_anomaly_timeline(hours: int = 24):
    """
    Get anomaly detection timeline for the last N hours
    Returns count of anomalies per hour
    """
    try:
        db = DuckDBManager(config.get_database_path())
        
        # Fetch anomaly alerts from last N hours
        start_time = datetime.now() - timedelta(hours=hours)
        
        # Query alerts
        query = """
            SELECT 
                DATE_TRUNC('hour', created_at) as hour,
                COUNT(*) as count,
                AVG(priority_score) as avg_score
            FROM alerts 
            WHERE detection_method = 'anomaly_detection'
              AND created_at >= ?
            GROUP BY DATE_TRUNC('hour', created_at)
            ORDER BY hour
        """
        
        results = db.execute_query(query, [start_time])
        
        timeline_data = [
            {
                "timestamp": str(row[0]),
                "count": row[1],
                "avgScore": round(row[2] if row[2] else 0, 2)
            }
            for row in results
        ]
        
        db.close()
        
        return {
            "success": True,
            "data": timeline_data,
            "timeRange": f"Last {hours} hours"
        }
        
    except Exception as e:
        logger.error("Error fetching anomaly timeline", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/anomalies/baselines")
async def get_baseline_metrics():
    """
    Get current baseline metrics and their values
    """
    try:
        db = DuckDBManager(config.get_database_path())
        baseline_mgr = BaselineManager(db)
        
        baselines = baseline_mgr.baselines
        
        metrics_data = []
        for metric_name, data in baselines.items():
            metrics_data.append({
                "name": metric_name,
                "mean": round(data.get("mean", 0), 2),
                "std": round(data.get("std", 0), 2),
                "min": round(data.get("min", 0), 2),
                "max": round(data.get("max", 0), 2),
                "median": round(data.get("median", 0), 2),
                "samples": data.get("count", 0)
            })
        
        db.close()
        
        return {
            "success": True,
            "metrics": metrics_data
        }
        
    except Exception as e:
        logger.error("Error fetching baselines", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/anomalies/distribution")
async def get_anomaly_distribution(limit: int = 100):
    """
    Get distribution of anomalies by source IP
    """
    try:
        db = DuckDBManager(config.get_database_path())
        
        query = """
            SELECT 
                source_ip,
                COUNT(*) as anomaly_count,
                MAX(priority_score) as max_score
            FROM alerts 
            WHERE detection_method = 'anomaly_detection'
              AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY anomaly_count DESC
            LIMIT ?
        """
        
        results = db.execute_query(query, [limit])
        
        distribution_data = [
            {
                "ip": row[0],
                "count": row[1],
                "maxScore": round(row[2] if row[2] else 0, 2)
            }
            for row in results
        ]
        
        db.close()
        
        return {
            "success": True,
            "data": distribution_data
        }
        
    except Exception as e:
        logger.error("Error fetching anomaly distribution", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/anomalies/severity")
async def get_anomaly_by_severity():
    """
    Get count of anomalies grouped by severity
    """
    try:
        db = DuckDBManager(config.get_database_path())
        
        query = """
            SELECT 
                severity,
                COUNT(*) as count
            FROM alerts 
            WHERE detection_method = 'anomaly_detection'
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """
        
        results = db.execute_query(query)
        
        severity_data = [
            {
                "severity": row[0],
                "count": row[1]
            }
            for row in results
        ]
        
        db.close()
        
        return {
            "success": True,
            "data": severity_data
        }
        
    except Exception as e:
        logger.error("Error fetching severity distribution", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/anomalies/types")
async def get_anomaly_types():
    """
    Get count of anomalies by alert type
    """
    try:
        db = DuckDBManager(config.get_database_path())
        
        query = """
            SELECT 
                alert_type,
                COUNT(*) as count
            FROM alerts 
            WHERE detection_method = 'anomaly_detection'
              AND alert_type IS NOT NULL
            GROUP BY alert_type
            ORDER BY count DESC
            LIMIT 10
        """
        
        results = db.execute_query(query)
        
        types_data = [
            {
                "type": row[0],
                "count": row[1]
            }
            for row in results
        ]
        
        db.close()
        
        return {
            "success": True,
            "data": types_data
        }
        
    except Exception as e:
        logger.error("Error fetching anomaly types", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
