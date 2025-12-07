"""
FastAPI Main Application
Provides REST API endpoints for the log analyzer frontend
Includes automatic baseline initialization and continuous analysis
"""
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel
import structlog
import os

from storage.db_manager import DuckDBManager
from storage.models import LogEntry, Alert, Severity
from core.config import config
from analyzers.baseline_manager import BaselineManager
from analyzers.orchestrator import AnalysisOrchestrator
from services.analysis_service import AnalysisService
from services.baseline_scheduler import BaselineScheduler

# Import analytics routes
from api.routes import analytics

logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(
    title="Log Analyzer API",
    description="API for log analysis and security monitoring",
    version="1.0.0"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include analytics router
app.include_router(analytics.router)

# Initialize database
# Use parent directory's data folder since API runs from backend/
db_path = "../" + config.get_database_path()
db_manager = DuckDBManager(db_path)

# Global services (initialized on startup)
analysis_service: Optional[AnalysisService] = None
baseline_scheduler: Optional[BaselineScheduler] = None

# Response models
class LogResponse(BaseModel):
    id: str
    timestamp: str
    raw: Optional[str] = None
    appname: Optional[str] = None
    host: Optional[str] = None
    message: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    normalized: Optional[dict] = None
    metadata: Optional[dict] = None

class AlertResponse(BaseModel):
    id: str
    log_id: Optional[str] = None
    alert_type: Optional[str] = None
    detection_method: Optional[str] = None
    severity: str
    description: Optional[str] = None
    metadata: Optional[dict] = None
    created_at: datetime
    acknowledged: bool
    priority_score: float
    source_ip: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    # Enhanced fields for causation
    causation_info: Optional[dict] = None
    related_log: Optional[dict] = None

class StatsResponse(BaseModel):
    total_logs: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    logs_last_hour: int
    alerts_last_hour: int
    top_hosts: List[dict]
    top_alert_types: List[dict]
    # Anomaly detection metrics
    anomaly_alerts: int
    anomaly_alerts_last_hour: int
    top_anomaly_types: List[dict]

# API Endpoints

@app.on_event("startup")
async def startup_event():
    """Initialize services on API startup"""
    global analysis_service, baseline_scheduler
    
    logger.info("Starting up API...")
    
    try:
        # 1. Initialize baselines if they don't exist
        baseline_file = "../data/baselines.json"
        if not os.path.exists(baseline_file):
            logger.info("No baselines found, creating initial baselines...")
            baseline_manager = BaselineManager(db_manager, baseline_file=baseline_file)
            
            # Check if we have logs to create baselines from
            log_count = db_manager.count_logs()
            if log_count > 100:
                logger.info(f"Creating baselines from {log_count} existing logs")
                baseline_manager.update_all_baselines(historical_days=7)
                logger.info("Initial baselines created successfully")
            else:
                logger.warning(f"Only {log_count} logs available, baselines may be inaccurate")
                if log_count > 0:
                    baseline_manager.update_all_baselines(historical_days=1)
        else:
            logger.info("Baselines already exist", baseline_file=baseline_file)
        
        # 2. Initialize orchestrator
        orchestrator_config = {
            'analysis_interval': 60,
            'batch_size': 10000,
            'signature_dir': '../config/signatures',
            'blocked_ips_file': '../config/blocked_ips.txt',
            'baseline_file': baseline_file,
            'update_baselines_on_start': False  # Already done above
        }
        
        orchestrator = AnalysisOrchestrator(db_manager, orchestrator_config)
        logger.info("Orchestrator initialized")
        
        # 3. Start analysis service (continuous orchestrator)
        analysis_service = AnalysisService(orchestrator, interval=60)
        analysis_service.start()
        logger.info("Analysis service started (runs every 60 seconds)")
        
        # 4. Start baseline scheduler (daily updates)
        baseline_manager = BaselineManager(db_manager, baseline_file=baseline_file)
        baseline_scheduler = BaselineScheduler(
            baseline_manager,
            update_interval=86400,  # 24 hours
            historical_days=7
        )
        baseline_scheduler.start()
        logger.info("Baseline scheduler started (updates every 24 hours)")
        
        logger.info("API startup complete - automatic analysis is running")
        
    except Exception as e:
        logger.error("Error during startup", error=str(e), exc_info=True)
        # Don't fail startup, just log the error


@app.on_event("shutdown")
async def shutdown_event():
    """Gracefully shutdown services"""
    global analysis_service, baseline_scheduler
    
    logger.info("Shutting down API...")
    
    if analysis_service:
        analysis_service.stop()
    
    if baseline_scheduler:
        baseline_scheduler.stop()
    
    logger.info("API shutdown complete")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Log Analyzer API",
        "version": "1.0.0",
        "status": "running",
        "auto_analysis": analysis_service is not None and analysis_service.running,
        "baseline_scheduler": baseline_scheduler is not None and baseline_scheduler.running
    }

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        count = db_manager.count_logs()
        return {
            "status": "healthy",
            "database": "connected",
            "total_logs": count
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        raise HTTPException(status_code=500, detail="Service unhealthy")

@app.get("/api/v1/stats", response_model=StatsResponse)
async def get_stats():
    """Get dashboard statistics"""
    try:
        # Total logs
        total_logs = db_manager.count_logs()
        
        # Total alerts
        all_alerts = db_manager.fetch_alerts(limit=100000)
        total_alerts = len(all_alerts)
        
        # Alerts by severity
        critical_alerts = len([a for a in all_alerts if a.severity == Severity.CRITICAL])
        high_alerts = len([a for a in all_alerts if a.severity == Severity.HIGH])
        medium_alerts = len([a for a in all_alerts if a.severity == Severity.MEDIUM])
        low_alerts = len([a for a in all_alerts if a.severity == Severity.LOW])
        
        # Logs last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        logs_last_hour = db_manager.count_logs(start_time=one_hour_ago)
        
        # Alerts last hour
        alerts_last_hour = len(db_manager.fetch_alerts(start_time=one_hour_ago))
        
        # Top hosts (from recent logs)
        recent_logs = db_manager.fetch_logs(limit=1000)
        host_counts = {}
        for log in recent_logs:
            host = log.host or "unknown"
            host_counts[host] = host_counts.get(host, 0) + 1
        
        top_hosts = [
            {"host": host, "count": count}
            for host, count in sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        # Top alert types
        alert_type_counts = {}
        for alert in all_alerts[:1000]:  # Recent alerts
            alert_type = alert.alert_type or "unknown"
            alert_type_counts[alert_type] = alert_type_counts.get(alert_type, 0) + 1
        
        top_alert_types = [
            {"type": alert_type, "count": count}
            for alert_type, count in sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        # Anomaly detection metrics
        anomaly_alerts = [a for a in all_alerts if a.detection_method == 'anomaly_detection']
        anomaly_alerts_count = len(anomaly_alerts)
        anomaly_alerts_last_hour = len([a for a in anomaly_alerts if a.created_at >= one_hour_ago])
        
        # Top anomaly types
        anomaly_type_counts = {}
        for alert in anomaly_alerts[:1000]:  # Recent anomaly alerts
            alert_type = alert.alert_type or "unknown"
            anomaly_type_counts[alert_type] = anomaly_type_counts.get(alert_type, 0) + 1
        
        top_anomaly_types = [
            {"type": alert_type, "count": count}
            for alert_type, count in sorted(anomaly_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        return StatsResponse(
            total_logs=total_logs,
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            low_alerts=low_alerts,
            logs_last_hour=logs_last_hour,
            alerts_last_hour=alerts_last_hour,
            top_hosts=top_hosts,
            top_alert_types=top_alert_types,
            anomaly_alerts=anomaly_alerts_count,
            anomaly_alerts_last_hour=anomaly_alerts_last_hour,
            top_anomaly_types=top_anomaly_types
        )
    except Exception as e:
        logger.error("Error fetching stats", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/logs", response_model=List[LogResponse])
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    appname: Optional[str] = None,
    host: Optional[str] = None,
    search: Optional[str] = None
):
    """Get logs with optional filters"""
    try:
        filters = {}
        if appname:
            filters['appname'] = appname
        if host:
            filters['host'] = host
        
        logs = db_manager.fetch_logs(
            limit=limit,
            offset=offset,
            filters=filters if filters else None
        )
        
        # Filter by search term if provided
        if search:
            search_lower = search.lower()
            logs = [
                log for log in logs
                if (log.message and search_lower in log.message.lower()) or
                   (log.raw and search_lower in log.raw.lower())
            ]
        
        return [
            LogResponse(
                id=log.id,
                timestamp=log.timestamp,
                raw=log.raw,
                appname=log.appname,
                host=log.host,
                message=log.message,
                source_ip=log.get_source_ip(),
                user=log.get_user(),
                normalized=log.normalized,
                metadata=log.metadata
            )
            for log in logs
        ]
    except Exception as e:
        logger.error("Error fetching logs", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/alerts", response_model=List[AlertResponse])
async def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None
):
    """Get alerts with optional filters"""
    try:
        alerts = db_manager.fetch_alerts(
            limit=limit,
            severity=severity,
            acknowledged=acknowledged
        )
        
        # Fetch related logs for alerts
        log_ids = [a.log_id for a in alerts if a.log_id]
        related_logs = {}
        if log_ids:
            logs = db_manager.fetch_logs_by_ids(log_ids)
            related_logs = {log.id: log for log in logs}
        
        result = []
        for alert in alerts:
            # Build causation info from metadata
            causation_info = _build_causation_info(alert)
            
            # Get related log if available
            related_log = None
            if alert.log_id and alert.log_id in related_logs:
                log = related_logs[alert.log_id]
                related_log = {
                    'id': log.id,
                    'timestamp': log.timestamp,
                    'message': log.message,
                    'host': log.host,
                    'appname': log.appname,
                    'raw': log.raw[:500] if log.raw else None  # Truncate for API
                }
            
            result.append(AlertResponse(
                id=alert.id,
                log_id=alert.log_id,
                alert_type=alert.alert_type,
                detection_method=alert.detection_method,
                severity=alert.severity,
                description=alert.description,
                metadata=alert.metadata,
                created_at=alert.created_at,
                acknowledged=alert.acknowledged,
                priority_score=alert.priority_score or 0.0,
                source_ip=alert.source_ip,
                host=alert.host,
                user=alert.user,
                causation_info=_build_causation_info(alert),
                related_log=related_log
            ))
        
        return result
    except Exception as e:
        logger.error("Error fetching alerts", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/logs/{log_id}", response_model=LogResponse)
async def get_log_by_id(log_id: str):
    """Get a specific log by ID"""
    try:
        logs = db_manager.fetch_logs_by_ids([log_id])
        if not logs:
            raise HTTPException(status_code=404, detail="Log not found")
        
        log = logs[0]
        return LogResponse(
            id=log.id,
            timestamp=log.timestamp,
            raw=log.raw,
            appname=log.appname,
            host=log.host,
            message=log.message,
            source_ip=log.get_source_ip(),
            user=log.get_user(),
            normalized=log.normalized,
            metadata=log.metadata
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error fetching log", error=str(e), log_id=log_id)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/appnames")
async def get_appnames():
    """Get list of unique appnames"""
    try:
        # Query distinct appnames
        query = "SELECT DISTINCT appname FROM logs WHERE appname IS NOT NULL ORDER BY appname"
        result = db_manager.execute_query(query)
        appnames = [row[0] for row in result]
        return {"appnames": appnames}
    except Exception as e:
        logger.error("Error fetching appnames", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/hosts")
async def get_hosts():
    """Get list of unique hosts"""
    try:
        query = "SELECT DISTINCT host FROM logs WHERE host IS NOT NULL ORDER BY host"
        result = db_manager.execute_query(query)
        hosts = [row[0] for row in result]
        return {"hosts": hosts}
    except Exception as e:
        logger.error("Error fetching hosts", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/signatures")
async def get_signatures():
    """Get loaded signature information"""
    try:
        from pathlib import Path
        import yaml
        
        signatures_dir = Path("config/signatures")
        all_signatures = []
        
        if signatures_dir.exists():
            for sig_file in signatures_dir.glob("*.yaml"):
                with open(sig_file, 'r') as f:
                    data = yaml.safe_load(f)
                    if data and 'signatures' in data:
                        for sig in data['signatures']:
                            all_signatures.append({
                                'id': sig.get('id'),
                                'name': sig.get('name'),
                                'severity': sig.get('severity'),
                                'category': sig.get('category'),
                                'description': sig.get('description'),
                                'file': sig_file.name
                            })
        
        return {
            "total": len(all_signatures),
            "signatures": all_signatures
        }
    except Exception as e:
        logger.error("Error fetching signatures", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/system/info")
async def get_system_info():
    """Get system information"""
    try:
        import os
        from pathlib import Path
        
        db_path = Path(db_manager.db_path)
        db_size = db_path.stat().st_size if db_path.exists() else 0
        
        return {
            "database": {
                "path": str(db_path),
                "size_mb": round(db_size / (1024 * 1024), 2),
                "status": "connected"
            },
            "api": {
                "version": "1.0.0",
                "status": "running"
            }
        }
    except Exception as e:
        logger.error("Error fetching system info", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/alerts/stats")
async def get_alert_stats():
    """Get detailed alert statistics including anomaly detection metrics"""
    try:
        from datetime import datetime, timedelta
        
        # Get all alerts
        all_alerts = db_manager.fetch_alerts(limit=100000)
        
        # Time-based stats
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        alerts_24h = [a for a in all_alerts if a.created_at >= last_24h]
        alerts_7d = [a for a in all_alerts if a.created_at >= last_7d]
        
        # Detection method breakdown
        detection_methods = {}
        for alert in all_alerts[:1000]:
            method = alert.detection_method or "unknown"
            detection_methods[method] = detection_methods.get(method, 0) + 1
        
        # Alert type breakdown
        alert_types = {}
        for alert in all_alerts[:1000]:
            atype = alert.alert_type or "unknown"
            alert_types[atype] = alert_types.get(atype, 0) + 1
        
        # Anomaly detection specific metrics
        anomaly_alerts = [a for a in all_alerts if a.detection_method == 'anomaly_detection']
        anomaly_alerts_24h = [a for a in anomaly_alerts if a.created_at >= last_24h]
        anomaly_alerts_7d = [a for a in anomaly_alerts if a.created_at >= last_7d]
        
        # Anomaly type breakdown
        anomaly_types = {}
        for alert in anomaly_alerts[:1000]:
            atype = alert.alert_type or "unknown"
            anomaly_types[atype] = anomaly_types.get(atype, 0) + 1
        
        # Anomaly severity breakdown
        anomaly_severity = {}
        for alert in anomaly_alerts:
            severity = alert.severity or "unknown"
            anomaly_severity[severity] = anomaly_severity.get(severity, 0) + 1
        
        # Anomaly trend (last 24 hours, hourly buckets)
        anomaly_trend_24h = {}
        current_hour = last_24h.replace(minute=0, second=0, microsecond=0)
        while current_hour <= now:
            hour_key = current_hour.isoformat()
            anomaly_trend_24h[hour_key] = 0
            current_hour += timedelta(hours=1)
        
        for alert in anomaly_alerts_24h:
            alert_hour = alert.created_at.replace(minute=0, second=0, microsecond=0)
            hour_key = alert_hour.isoformat()
            if hour_key in anomaly_trend_24h:
                anomaly_trend_24h[hour_key] += 1
        
        return {
            "total_alerts": len(all_alerts),
            "alerts_24h": len(alerts_24h),
            "alerts_7d": len(alerts_7d),
            "detection_methods": [
                {"method": k, "count": v} 
                for k, v in sorted(detection_methods.items(), key=lambda x: x[1], reverse=True)
            ],
            "alert_types": [
                {"type": k, "count": v}
                for k, v in sorted(alert_types.items(), key=lambda x: x[1], reverse=True)[:10]
            ],
            # Anomaly detection metrics
            "anomaly_detection": {
                "total_anomalies": len(anomaly_alerts),
                "anomalies_24h": len(anomaly_alerts_24h),
                "anomalies_7d": len(anomaly_alerts_7d),
                "percentage_of_total": (len(anomaly_alerts) / len(all_alerts) * 100) if all_alerts else 0,
                "anomaly_types": [
                    {"type": k, "count": v}
                    for k, v in sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True)[:10]
                ],
                "severity_breakdown": {
                    k: v for k, v in sorted(anomaly_severity.items(), key=lambda x: x[1], reverse=True)
                },
                "trend_24h": [
                    {"time": k, "count": v}
                    for k, v in sorted(anomaly_trend_24h.items())
                ]
            }
        }
    except Exception as e:
        logger.error("Error fetching alert stats", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

def _build_causation_info(alert: Alert) -> dict:
    """Build detailed causation information from alert metadata"""
    metadata = alert.metadata or {}
    causation = {
        'detection_method': alert.detection_method,
        'alert_type': alert.alert_type,
        'summary': alert.description
    }
    
    # Add method-specific causation details
    if alert.detection_method == 'signature_detector':
        causation['signature_id'] = metadata.get('signature_id')
        causation['signature_name'] = metadata.get('signature_name')
        causation['matched_pattern'] = metadata.get('matched_pattern')
        causation['category'] = metadata.get('category')
    
    elif alert.detection_method == 'anomaly_detection':
        causation['metric'] = metadata.get('metric')
        causation['baseline_value'] = metadata.get('baseline_value')
        causation['observed_value'] = metadata.get('observed_value')
        causation['deviation'] = metadata.get('deviation')
        causation['z_score'] = metadata.get('z_score')
    
    elif alert.detection_method == 'heuristic_analyzer':
        causation['rule_id'] = metadata.get('rule_id')
        causation['rule_name'] = metadata.get('rule_name')
        causation['pattern_detected'] = metadata.get('pattern_detected')
        if 'failed_count' in metadata:
            causation['failed_attempts'] = metadata.get('failed_count')
        if 'unique_hosts' in metadata:
            causation['hosts_accessed'] = metadata.get('unique_hosts')
        if 'bytes_transferred' in metadata:
            causation['data_transferred'] = metadata.get('bytes_transferred')
    
    elif alert.detection_method == 'behavioral_analyzer':
        causation['deviation_type'] = metadata.get('deviation_type')
        causation['user_id'] = metadata.get('user_id')
        if metadata.get('deviation_type') == 'time':
            causation['unusual_hour'] = metadata.get('login_hour')
            causation['typical_hours'] = metadata.get('typical_hours')
        elif metadata.get('deviation_type') == 'location':
            causation['unusual_ip'] = alert.source_ip
            causation['typical_ips'] = metadata.get('typical_ips')
        elif metadata.get('deviation_type') == 'resource':
            causation['unusual_resource'] = metadata.get('resource')
    
    elif alert.detection_method == 'network_analyzer':
        causation['network_anomaly_type'] = alert.alert_type
        if 'unique_ports' in metadata:
            causation['ports_scanned'] = metadata.get('unique_ports')
        if 'connection_count' in metadata:
            causation['connections'] = metadata.get('connection_count')
        if 'coefficient_of_variation' in metadata:
            causation['beaconing_regularity'] = metadata.get('coefficient_of_variation')
    
    elif alert.detection_method == 'rule_engine':
        causation['rule_id'] = metadata.get('rule_id')
        causation['rule_name'] = metadata.get('rule_name')
        causation['mitre_technique'] = metadata.get('mitre_technique')
        causation['mitre_tactic'] = metadata.get('mitre_tactic')
    
    elif alert.detection_method == 'threat_intel_matcher':
        causation['indicator_type'] = metadata.get('indicator_type')
        causation['indicator_value'] = metadata.get('indicator_value')
        causation['threat_type'] = metadata.get('threat_type')
        causation['confidence'] = metadata.get('confidence')
        causation['source'] = metadata.get('source')
    
    return causation

@app.get("/api/v1/anomalies/trend")
async def get_anomaly_trend(hours: int = Query(24, ge=1, le=168)):
    """Get anomaly detection trend over time"""
    try:
        from datetime import datetime, timedelta
        
        # Get anomaly alerts
        all_alerts = db_manager.fetch_alerts(limit=100000)
        anomaly_alerts = [a for a in all_alerts if a.detection_method == 'anomaly_detection']
        
        # Group by time buckets (hourly)
        now = datetime.now()
        start_time = now - timedelta(hours=hours)
        
        # Create hourly buckets
        buckets = {}
        current = start_time.replace(minute=0, second=0, microsecond=0)
        
        while current <= now:
            buckets[current.isoformat()] = 0
            current += timedelta(hours=1)
        
        # Count anomalies per hour
        for alert in anomaly_alerts:
            if alert.created_at >= start_time:
                # Round to nearest hour
                alert_hour = alert.created_at.replace(minute=0, second=0, microsecond=0)
                hour_key = alert_hour.isoformat()
                if hour_key in buckets:
                    buckets[hour_key] += 1
        
        # Convert to list format
        trend_data = [
            {"time": time, "count": count}
            for time, count in sorted(buckets.items())
        ]
        
        return {
            "period_hours": hours,
            "total_anomalies": len([a for a in anomaly_alerts if a.created_at >= start_time]),
            "trend": trend_data
        }
    except Exception as e:
        logger.error("Error fetching anomaly trend", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert_by_id(alert_id: str):
    """Get a specific alert by ID with full causation details"""
    try:
        all_alerts = db_manager.fetch_alerts(limit=100000)
        alert = next((a for a in all_alerts if a.id == alert_id), None)
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Build causation info
        causation_info = _build_causation_info(alert)
        
        # Get related log
        related_log = None
        if alert.log_id:
            logs = db_manager.fetch_logs_by_ids([alert.log_id])
            if logs:
                log = logs[0]
                related_log = {
                    'id': log.id,
                    'timestamp': log.timestamp,
                    'message': log.message,
                    'host': log.host,
                    'appname': log.appname,
                    'raw': log.raw,
                    'normalized': log.normalized,
                    'metadata': log.metadata
                }
        
        return AlertResponse(
            id=alert.id,
            log_id=alert.log_id,
            alert_type=alert.alert_type,
            detection_method=alert.detection_method,
            severity=alert.severity,
            description=alert.description,
            metadata=alert.metadata,
            created_at=alert.created_at,
            acknowledged=alert.acknowledged,
            priority_score=alert.priority_score or 0.0,
            source_ip=alert.source_ip,
            host=alert.host,
            user=alert.user,
            causation_info=causation_info,
            related_log=related_log
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error fetching alert", error=str(e), alert_id=alert_id)
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
