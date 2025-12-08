"""
Brute Force Detector
Detects brute force and authentication-related attacks through pattern counting and time-windowed analysis

Focus: Authentication attacks including SSH brute force, password spraying, credential stuffing
"""
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import structlog
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


class BruteForceDetector:
    """
    Detects brute force authentication attacks using:
    - Failed login counting within time windows
    - Source IP tracking
    - Pattern matching for auth failures
    """
    
    def __init__(self, rules_file: str = "config/signatures/auth_attacks.yaml"):
        """
        Initialize brute force detector
        
        Args:
            rules_file: Path to YAML file with brute force rules
        """
        self.rules_file = Path(rules_file)
        self.rules = []
        self.failed_attempts = defaultdict(list)  # {ip: [(timestamp, log_id), ...]}
        self.time_window = 300  # Default 5 minutes
        
        self._load_rules()
        logger.info("BruteForceDetector initialized", rules_count=len(self.rules))
    
    def _load_rules(self):
        """Load brute force detection rules from YAML"""
        if not self.rules_file.exists():
            logger.warning("Rules file not found", file=str(self.rules_file))
            return
        
        try:
            with open(self.rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if data and 'signatures' in data:
                self.rules = data['signatures']
                logger.info("Loaded brute force rules", count=len(self.rules))
        except Exception as e:
            logger.error("Error loading rules", error=str(e), file=str(self.rules_file))
    
    def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs for brute force attacks
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for detected brute force attempts
        """
        alerts = []
        
        # Group logs by source IP for temporal analysis
        ip_logs = defaultdict(list)
        for log in logs:
            source_ip = log.get_source_ip()
            if source_ip:
                ip_logs[source_ip].append(log)
        
        # Analyze each IP's activity
        for source_ip, ip_log_list in ip_logs.items():
            # Check for failed login patterns
            failed_logins = self._identify_failed_logins(ip_log_list)
            
            if failed_logins:
                # Time-windowed analysis
                brute_force_alerts = self._detect_brute_force_window(
                    source_ip, 
                    failed_logins
                )
                alerts.extend(brute_force_alerts)
        
        # Also check individual logs against signature patterns
        for log in logs:
            signature_alerts = self._check_signatures(log)
            alerts.extend(signature_alerts)
        
        logger.info(
            "Brute force analysis complete",
            logs_analyzed=len(logs),
            alerts_generated=len(alerts)
        )
        
        return alerts
    
    def _identify_failed_logins(self, logs: List[LogEntry]) -> List[LogEntry]:
        """
        Identify failed login attempts from logs
        
        Args:
            logs: Logs from a single source IP
            
        Returns:
            List of logs that are failed login attempts
        """
        failed_logins = []
        
        # Patterns indicating failed authentication
        failed_patterns = [
            r"(?i)failed password",
            r"(?i)authentication failure",
            r"(?i)invalid user",
            r"(?i)login.*failed",
            r"(?i)incorrect.*password",
            r"(?i)access denied"
        ]
        
        for log in logs:
            message = log.message or log.raw or ""
            
            for pattern in failed_patterns:
                if re.search(pattern, message):
                    failed_logins.append(log)
                    break
        
        return failed_logins
    
    def _detect_brute_force_window(
        self, 
        source_ip: str, 
        failed_logins: List[LogEntry],
        window_seconds: int = 300,
        threshold: int = 5
    ) -> List[Alert]:
        """
        Detect brute force attacks using time-windowed counting
        
        Args:
            source_ip: Source IP being analyzed
            failed_logins: List of failed login attempts
            window_seconds: Time window in seconds (default 5 minutes)
            threshold: Number of failures to trigger alert (default 5)
            
        Returns:
            List of brute force alerts
        """
        alerts = []
        
        if len(failed_logins) < threshold:
            return alerts
        
        # Sort by timestamp
        sorted_logins = sorted(
            failed_logins, 
            key=lambda x: x.get_timestamp() or datetime.now()
        )
        
        # Sliding window analysis
        for i in range(len(sorted_logins)):
            window_start = sorted_logins[i].get_timestamp()
            if not window_start:
                continue
            
            window_end = window_start + timedelta(seconds=window_seconds)
            
            # Count failures in this window
            failures_in_window = []
            for log in sorted_logins[i:]:
                log_time = log.get_timestamp()
                if log_time and window_start <= log_time <= window_end:
                    failures_in_window.append(log)
                elif log_time and log_time > window_end:
                    break
            
            # Check if threshold exceeded
            if len(failures_in_window) >= threshold:
                # Extract usernames attempted
                usernames = set()
                for log in failures_in_window:
                    user = log.get_user()
                    if user:
                        usernames.add(user)
                
                # Create alert
                alert = Alert(
                    id=str(uuid.uuid4()),
                    log_id=sorted_logins[i].id,
                    alert_type="brute_force_attack",
                    detection_method="brute_force_detector",
                    severity=Severity.HIGH if len(failures_in_window) >= 10 else Severity.MEDIUM,
                    description=f"Brute force attack detected: {len(failures_in_window)} failed login attempts from {source_ip} in {window_seconds}s",
                    metadata={
                        "source_ip": source_ip,
                        "failed_attempts": len(failures_in_window),
                        "time_window_seconds": window_seconds,
                        "usernames_targeted": list(usernames),
                        "first_attempt": window_start.isoformat(),
                        "last_attempt": failures_in_window[-1].get_timestamp().isoformat() if failures_in_window[-1].get_timestamp() else None
                    },
                    created_at=datetime.now(),
                    source_ip=source_ip,
                    host=sorted_logins[i].host
                )
                
                alerts.append(alert)
                
                # Only alert once per window to avoid duplicates
                break
        
        return alerts
    
    def _check_signatures(self, log: LogEntry) -> List[Alert]:
        """
        Check log against signature patterns
        
        Args:
            log: Log entry to check
            
        Returns:
            List of alerts (0 or 1)
        """
        alerts = []
        
        for rule in self.rules:
            if self._matches_signature(log, rule):
                alert = self._create_alert(log, rule)
                alerts.append(alert)
                # Only trigger first matching rule to avoid duplicate alerts
                break
        
        return alerts
    
    def _matches_signature(self, log: LogEntry, rule: Dict[str, Any]) -> bool:
        """
        Check if log matches signature rule
        
        Args:
            log: Log entry
            rule: Signature rule
            
        Returns:
            True if log matches rule
        """
        patterns = rule.get('patterns', [])
        if not patterns:
            return False
        
        # Get fields to check
        fields = rule.get('fields', ['message', 'raw'])
        
        # Check each pattern
        for pattern_def in patterns:
            if isinstance(pattern_def, dict):
                pattern = pattern_def.get('regex', '')
            else:
                pattern = pattern_def
            
            if not pattern:
                continue
            
            # Check pattern against specified fields
            for field_path in fields:
                field_value = self._extract_field(log, field_path)
                if field_value and re.search(pattern, str(field_value)):
                    return True
        
        return False
    
    def _extract_field(self, log: LogEntry, field_path: str) -> Any:
        """
        Extract field value from log using dot notation
        
        Args:
            log: Log entry
            field_path: Field path (e.g., 'message', 'normalized.user')
            
        Returns:
            Field value or None
        """
        parts = field_path.split('.')
        
        # Handle top-level fields
        if len(parts) == 1:
            return getattr(log, parts[0], None)
        
        # Handle nested fields (e.g., normalized.user)
        if parts[0] == 'normalized' and log.normalized:
            return log.normalized.get(parts[1])
        
        if parts[0] == 'metadata' and log.metadata:
            return log.metadata.get(parts[1])
        
        return None
    
    def _create_alert(self, log: LogEntry, rule: Dict[str, Any]) -> Alert:
        """
        Create alert from signature match
        
        Args:
            log: Matched log
            rule: Matched signature rule
            
        Returns:
            Alert object
        """
        # Map signature severity to alert severity
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        
        severity = severity_map.get(
            rule.get('severity', 'medium').lower(),
            Severity.MEDIUM
        )
        
        return Alert(
            id=str(uuid.uuid4()),
            log_id=log.id,
            alert_type=rule.get('category', 'authentication_attack'),
            detection_method='brute_force_detector',
            severity=severity,
            description=rule.get('description', rule.get('name', 'Authentication attack detected')),
            metadata={
                'signature_id': rule.get('id'),
                'signature_name': rule.get('name'),
                'category': rule.get('category')
            },
            created_at=datetime.now(),
            source_ip=log.get_source_ip(),
            user=log.get_user(),
            host=log.host
        )
    
    def reload_rules(self):
        """Reload rules from disk"""
        self.rules = []
        self._load_rules()
        logger.info("Rules reloaded", count=len(self.rules))
