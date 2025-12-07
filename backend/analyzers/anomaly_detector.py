"""
Anomaly Detector
Detects unusual patterns using statistical and ML-based methods
"""
import structlog
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    structlog.get_logger().warning("scikit-learn not available, ML-based detection disabled")

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


# Anomaly detection metrics configuration
ANOMALY_METRICS = {
    'login_frequency': {
        'description': 'Hourly login count',
        'method': 'z_score',
        'threshold': 3.0,
        'severity': Severity.MEDIUM,
        'window_minutes': 60
    },
    'failed_login_rate': {
        'description': 'Failed login attempts per 5 minutes',
        'method': 'moving_average',
        'threshold': 2.5,
        'severity': Severity.HIGH,
        'window_minutes': 5
    },
    'requests_per_ip': {
        'description': 'Requests from single IP',
        'method': 'z_score',
        'threshold': 3.5,
        'severity': Severity.MEDIUM,
        'window_minutes': 60
    },
    'error_rate': {
        'description': 'Error rate per hour',
        'method': 'moving_average',
        'threshold': 2.0,
        'severity': Severity.MEDIUM,
        'window_minutes': 60
    },
    'unique_destinations': {
        'description': 'Unique destination IPs per source',
        'method': 'isolation_forest' if SKLEARN_AVAILABLE else 'iqr',
        'threshold': 0.1,  # contamination rate for isolation forest
        'severity': Severity.HIGH,
        'window_minutes': 60
    },
    'command_execution_rate': {
        'description': 'Command execution frequency',
        'method': 'z_score',
        'threshold': 3.0,
        'severity': Severity.HIGH,
        'window_minutes': 60
    }
}


class AnomalyDetector:
    """
    Detects anomalies using statistical and ML-based methods
    """
    
    def __init__(self, baseline_manager):
        """
        Initialize anomaly detector
        
        Args:
            baseline_manager: BaselineManager instance for historical baselines
        """
        self.baseline_manager = baseline_manager
        self.name = "anomaly_detector"
        
        logger.info("Anomaly detector initialized", 
                   sklearn_available=SKLEARN_AVAILABLE,
                   metrics_count=len(ANOMALY_METRICS))
    
    async def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs for anomalies
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for detected anomalies
        """
        if not logs:
            return []
        
        logger.info("Starting anomaly detection", log_count=len(logs))
        alerts = []
        
        try:
            # Detect different types of anomalies
            alerts.extend(self._detect_login_anomalies(logs))
            alerts.extend(self._detect_request_anomalies(logs))
            alerts.extend(self._detect_error_anomalies(logs))
            alerts.extend(self._detect_network_anomalies(logs))
            alerts.extend(self._detect_command_anomalies(logs))
            
            logger.info("Anomaly detection completed", 
                       alerts_generated=len(alerts),
                       log_count=len(logs))
            
        except Exception as e:
            logger.error("Error in anomaly detection", error=str(e))
        
        return alerts
    
    def _detect_login_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect anomalies in login patterns"""
        alerts = []
        
        # Count logins and failed logins
        login_count = 0
        failed_login_count = 0
        failed_logins_by_ip = defaultdict(int)
        
        for log in logs:
            if not log.message:
                continue
            
            message_lower = log.message.lower()
            
            if 'login' in message_lower or 'accepted' in message_lower:
                login_count += 1
            
            if 'failed' in message_lower and ('login' in message_lower or 'password' in message_lower):
                failed_login_count += 1
                source_ip = log.get_source_ip()
                if source_ip:
                    failed_logins_by_ip[source_ip] += 1
        
        # Check login frequency anomaly
        baseline = self.baseline_manager.get_baseline('login_frequency')
        if baseline and login_count > 0:
            anomaly = self._check_z_score_anomaly(
                login_count,
                baseline,
                ANOMALY_METRICS['login_frequency']['threshold']
            )
            
            if anomaly:
                alerts.append(self._create_alert(
                    alert_type='login_frequency_anomaly',
                    description=f"Unusual login frequency detected: {login_count} logins (baseline: {baseline['mean']:.1f} ± {baseline['std']:.1f})",
                    severity=ANOMALY_METRICS['login_frequency']['severity'],
                    metadata={
                        'current_value': login_count,
                        'baseline_mean': baseline['mean'],
                        'baseline_std': baseline['std'],
                        'z_score': anomaly['z_score']
                    }
                ))
        
        # Check failed login rate
        baseline = self.baseline_manager.get_baseline('failed_login_rate')
        if baseline and failed_login_count > 0:
            anomaly = self._check_z_score_anomaly(
                failed_login_count,
                baseline,
                ANOMALY_METRICS['failed_login_rate']['threshold']
            )
            
            if anomaly:
                alerts.append(self._create_alert(
                    alert_type='failed_login_anomaly',
                    description=f"Unusual failed login rate: {failed_login_count} failures (baseline: {baseline['mean']:.1f})",
                    severity=ANOMALY_METRICS['failed_login_rate']['severity'],
                    metadata={
                        'current_value': failed_login_count,
                        'baseline_mean': baseline['mean'],
                        'z_score': anomaly['z_score'],
                        'top_ips': dict(Counter(failed_logins_by_ip).most_common(5))
                    }
                ))
        
        # Check for brute force from single IP
        for ip, count in failed_logins_by_ip.items():
            if count >= 5:  # 5+ failed logins from same IP
                alerts.append(self._create_alert(
                    alert_type='brute_force_attempt',
                    description=f"Possible brute force attack from {ip}: {count} failed login attempts",
                    severity=Severity.HIGH,
                    source_ip=ip,
                    metadata={'failed_attempts': count}
                ))
        
        return alerts
    
    def _detect_request_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect anomalies in request patterns"""
        alerts = []
        
        # Count requests per IP
        requests_by_ip = defaultdict(int)
        
        for log in logs:
            source_ip = log.get_source_ip()
            if source_ip:
                requests_by_ip[source_ip] += 1
        
        if not requests_by_ip:
            return alerts
        
        # Get baseline
        baseline = self.baseline_manager.get_baseline('requests_per_ip')
        
        # Check each IP
        for ip, count in requests_by_ip.items():
            if baseline:
                anomaly = self._check_z_score_anomaly(
                    count,
                    baseline,
                    ANOMALY_METRICS['requests_per_ip']['threshold']
                )
                
                if anomaly:
                    alerts.append(self._create_alert(
                        alert_type='request_rate_anomaly',
                        description=f"Unusual request rate from {ip}: {count} requests (baseline: {baseline['mean']:.1f})",
                        severity=ANOMALY_METRICS['requests_per_ip']['severity'],
                        source_ip=ip,
                        metadata={
                            'request_count': count,
                            'baseline_mean': baseline['mean'],
                            'z_score': anomaly['z_score']
                        }
                    ))
            else:
                # Without baseline, use simple threshold
                if count > 100:  # More than 100 requests
                    alerts.append(self._create_alert(
                        alert_type='high_request_rate',
                        description=f"High request rate from {ip}: {count} requests",
                        severity=Severity.MEDIUM,
                        source_ip=ip,
                        metadata={'request_count': count}
                    ))
        
        return alerts
    
    def _detect_error_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect anomalies in error rates"""
        alerts = []
        
        # Count errors
        error_count = 0
        error_types = defaultdict(int)
        
        for log in logs:
            if not log.message:
                continue
            
            message_lower = log.message.lower()
            
            if any(keyword in message_lower for keyword in ['error', 'fail', 'exception', 'denied', 'forbidden']):
                error_count += 1
                
                # Categorize error type
                if 'denied' in message_lower or 'forbidden' in message_lower:
                    error_types['access_denied'] += 1
                elif 'exception' in message_lower:
                    error_types['exception'] += 1
                elif '500' in message_lower or '503' in message_lower:
                    error_types['server_error'] += 1
                else:
                    error_types['other'] += 1
        
        # Check error rate
        baseline = self.baseline_manager.get_baseline('error_rate')
        if baseline and error_count > 0:
            anomaly = self._check_z_score_anomaly(
                error_count,
                baseline,
                ANOMALY_METRICS['error_rate']['threshold']
            )
            
            if anomaly:
                alerts.append(self._create_alert(
                    alert_type='error_rate_anomaly',
                    description=f"Unusual error rate: {error_count} errors (baseline: {baseline['mean']:.1f})",
                    severity=ANOMALY_METRICS['error_rate']['severity'],
                    metadata={
                        'error_count': error_count,
                        'baseline_mean': baseline['mean'],
                        'z_score': anomaly['z_score'],
                        'error_breakdown': dict(error_types)
                    }
                ))
        
        return alerts
    
    def _detect_network_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect anomalies in network patterns"""
        alerts = []
        
        # Track unique destinations per source
        destinations_by_source = defaultdict(set)
        
        for log in logs:
            source_ip = log.get_source_ip()
            if source_ip and log.normalized:
                # Try to extract destination IP from normalized data
                dest_ip = log.normalized.get('dest_ip') or log.normalized.get('destination_ip')
                if dest_ip:
                    destinations_by_source[source_ip].add(dest_ip)
        
        # Check for port scanning (many destinations from one source)
        for source_ip, destinations in destinations_by_source.items():
            dest_count = len(destinations)
            
            if dest_count >= 10:  # Contacted 10+ unique destinations
                alerts.append(self._create_alert(
                    alert_type='port_scan_detected',
                    description=f"Possible port scan from {source_ip}: {dest_count} unique destinations",
                    severity=Severity.HIGH,
                    source_ip=source_ip,
                    metadata={
                        'destination_count': dest_count,
                        'destinations': list(destinations)[:20]  # First 20
                    }
                ))
        
        return alerts
    
    def _detect_command_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect anomalies in command execution patterns"""
        alerts = []
        
        # Count command executions
        command_count = 0
        suspicious_commands = []
        
        for log in logs:
            if not log.message:
                continue
            
            message_lower = log.message.lower()
            
            # Look for command execution indicators
            if any(keyword in message_lower for keyword in ['sudo', 'exec', 'command', 'shell', 'bash']):
                command_count += 1
                
                # Check for suspicious commands
                if any(cmd in message_lower for cmd in ['rm -rf', 'chmod 777', 'wget', 'curl', 'nc ', 'netcat']):
                    suspicious_commands.append(log.message[:100])
        
        # Check command execution rate
        baseline = self.baseline_manager.get_baseline('command_execution_rate')
        if baseline and command_count > 0:
            anomaly = self._check_z_score_anomaly(
                command_count,
                baseline,
                ANOMALY_METRICS['command_execution_rate']['threshold']
            )
            
            if anomaly:
                alerts.append(self._create_alert(
                    alert_type='command_execution_anomaly',
                    description=f"Unusual command execution rate: {command_count} commands (baseline: {baseline['mean']:.1f})",
                    severity=ANOMALY_METRICS['command_execution_rate']['severity'],
                    metadata={
                        'command_count': command_count,
                        'baseline_mean': baseline['mean'],
                        'z_score': anomaly['z_score'],
                        'suspicious_commands': suspicious_commands[:5]
                    }
                ))
        
        # Alert on suspicious commands even without anomaly
        if suspicious_commands:
            alerts.append(self._create_alert(
                alert_type='suspicious_commands',
                description=f"Suspicious commands detected: {len(suspicious_commands)} instances",
                severity=Severity.HIGH,
                metadata={'commands': suspicious_commands[:10]}
            ))
        
        return alerts
    
    def _check_z_score_anomaly(self, value: float, baseline: Dict, threshold: float) -> Optional[Dict]:
        """
        Check if value is anomalous using z-score
        
        Args:
            value: Current value
            baseline: Baseline statistics
            threshold: Z-score threshold
            
        Returns:
            Anomaly details or None
        """
        mean = baseline.get('mean', 0)
        std = baseline.get('std', 0)
        
        if std == 0:
            return None
        
        z_score = (value - mean) / std
        
        if abs(z_score) > threshold:
            return {
                'value': value,
                'z_score': z_score,
                'mean': mean,
                'std': std
            }
        
        return None
    
    def _check_iqr_anomaly(self, value: float, baseline: Dict, multiplier: float = 1.5) -> Optional[Dict]:
        """
        Check if value is anomalous using IQR method
        
        Args:
            value: Current value
            baseline: Baseline statistics
            multiplier: IQR multiplier (default 1.5)
            
        Returns:
            Anomaly details or None
        """
        q1 = baseline.get('q1', 0)
        q3 = baseline.get('q3', 0)
        iqr = baseline.get('iqr', 0)
        
        lower_bound = q1 - (multiplier * iqr)
        upper_bound = q3 + (multiplier * iqr)
        
        if value < lower_bound or value > upper_bound:
            return {
                'value': value,
                'lower_bound': lower_bound,
                'upper_bound': upper_bound,
                'q1': q1,
                'q3': q3,
                'iqr': iqr
            }
        
        return None
    
    def _create_alert(
        self,
        alert_type: str,
        description: str,
        severity: Severity,
        source_ip: Optional[str] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> Alert:
        """Create an alert for detected anomaly"""
        return Alert(
            log_id=None,
            alert_type=alert_type,
            detection_method='anomaly_detection',
            severity=severity,
            description=description,
            source_ip=source_ip,
            host=host,
            user=user,
            metadata=metadata or {},
            created_at=datetime.now(),
            acknowledged=False,
            priority_score=self._calculate_priority(severity)
        )
    
    def _calculate_priority(self, severity: Severity) -> float:
        """Calculate priority score based on severity"""
        severity_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.25
        }
        return severity_scores.get(severity, 0.5)
