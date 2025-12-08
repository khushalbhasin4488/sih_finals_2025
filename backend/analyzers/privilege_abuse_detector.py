"""
Privilege Abuse Detector
Detects privilege escalation and account manipulation through command analysis

Focus: Sudo abuse, privilege escalation, account creation/modification, lateral movement
"""
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import structlog
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


class PrivilegeAbuseDetector:
    """
    Detects privilege escalation and abuse using:
    - Suspicious sudo command detection
    - Account creation/modification tracking
    - Privilege change monitoring
    - Lateral movement indicators
    """
    
    def __init__(self, rules_file: str = "config/signatures/privilege_abuse.yaml"):
        """
        Initialize privilege abuse detector
        
        Args:
            rules_file: Path to YAML file with privilege abuse signatures
        """
        self.rules_file = Path(rules_file)
        self.rules = []
        
        # High-risk sudo patterns
        self.sudo_patterns = [
            (r"sudo\s+su\s*-", "Root shell escalation", Severity.CRITICAL),
            (r"sudo\s+-i", "Interactive root shell", Severity.CRITICAL),
            (r"sudo\s+/bin/(ba)?sh", "Sudo shell spawn", Severity.CRITICAL),
            (r"sudo\s+.*passwd", "Password change via sudo", Severity.HIGH),
            (r"sudo\s+usermod.*-G.*root", "Adding user to root group", Severity.CRITICAL)
        ]
        
        # User manipulation patterns
        self.user_patterns = [
            (r"useradd", "User account creation", Severity.MEDIUM),
            (r"adduser", "User account creation", Severity.MEDIUM),
            (r"userdel", "User account deletion", Severity.MEDIUM),
            (r"usermod", "User account modification", Severity.MEDIUM),
            (r"passwd\s+\w+", "Password change", Severity.LOW)
        ]
        
        self._load_rules()
        logger.info("PrivilegeAbuseDetector initialized", rules_count=len(self.rules))
    
    def _load_rules(self):
        """Load privilege abuse signatures from YAML"""
        if not self.rules_file.exists():
            logger.warning("Rules file not found, using built-in patterns", file=str(self.rules_file))
            return
        
        try:
            with open(self.rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if data and 'signatures' in data:
                self.rules = data['signatures']
                logger.info("Loaded privilege abuse rules", count=len(self.rules))
        except Exception as e:
            logger.error("Error loading rules", error=str(e), file=str(self.rules_file))
    
    def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs for privilege abuse
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for detected privilege abuse
        """
        alerts = []
        
        # Filter for system and auth logs
        system_logs = [
            log for log in logs 
            if log.source_type in ['system', 'auth', 'audit'] or
               log.appname in ['sudo', 'su', 'systemd', 'auditd']
        ]
        
        logger.info(
            "Analyzing system logs for privilege abuse",
            total_logs=len(logs),
            system_logs=len(system_logs)
        )
        
        for log in system_logs:
            # Check built-in patterns first
            pattern_alerts = self._check_builtin_patterns(log)
            alerts.extend(pattern_alerts)
            
            # Check signature rules if loaded
            if self.rules:
                signature_alerts = self._check_signatures(log)
                alerts.extend(signature_alerts)
        
        logger.info(
            "Privilege abuse analysis complete",
            logs_analyzed=len(system_logs),
            alerts_generated=len(alerts)
        )
        
        return alerts
    
    def _check_builtin_patterns(self, log: LogEntry) -> List[Alert]:
        """
        Check log against built-in privilege abuse patterns
        
        Args:
            log: Log entry to check
            
        Returns:
            List of alerts (0 or 1)
        """
        alerts = []
        message = log.message or log.raw or ""
        
        # Check sudo patterns
        for pattern, description, severity in self.sudo_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                # Extract the command for context
                command = self._extract_command(message)
                
                alert = Alert(
                    id=str(uuid.uuid4()),
                    log_id=log.id,
                    alert_type="privilege_escalation",
                    detection_method="privilege_abuse_detector",
                    severity=severity,
                    description=description,
                    metadata={
                        "pattern": pattern,
                        "command": command,
                        "category": "sudo_abuse"
                    },
                    created_at=datetime.now(),
                    user=log.get_user(),
                    host=log.host
                )
                alerts.append(alert)
                return alerts  # Only one alert per log
        
        # Check user manipulation patterns
        for pattern, description, severity in self.user_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                command = self._extract_command(message)
                
                alert = Alert(
                    id=str(uuid.uuid4()),
                    log_id=log.id,
                    alert_type="account_manipulation",
                    detection_method="privilege_abuse_detector",
                    severity=severity,
                    description=description,
                    metadata={
                        "pattern": pattern,
                        "command": command,
                        "category": "user_manipulation"
                    },
                    created_at=datetime.now(),
                    user=log.get_user(),
                    host=log.host
                )
                alerts.append(alert)
                return alerts
        
        return alerts
    
    def _check_signatures(self, log: LogEntry) -> List[Alert]:
        """
        Check log against signature rules
        
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
                return alerts  # Only first match
        
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
        
        fields = rule.get('fields', ['message', 'raw'])
        
        # Check patterns against fields
        for pattern_def in patterns:
            if isinstance(pattern_def, dict):
                pattern = pattern_def.get('regex', '')
            else:
                pattern = pattern_def
            
            if not pattern:
                continue
            
            for field_path in fields:
                field_value = self._extract_field(log, field_path)
                if field_value and re.search(pattern, str(field_value), re.IGNORECASE):
                    return True
        
        return False
    
    def _extract_field(self, log: LogEntry, field_path: str) -> Any:
        """
        Extract field value from log using dot notation
        
        Args:
            log: Log entry
            field_path: Field path (e.g., 'message', 'normalized.command')
            
        Returns:
            Field value or None
        """
        parts = field_path.split('.')
        
        # Handle top-level fields
        if len(parts) == 1:
            return getattr(log, parts[0], None)
        
        # Handle nested fields
        if parts[0] == 'normalized' and log.normalized:
            return log.normalized.get(parts[1])
        
        if parts[0] == 'metadata' and log.metadata:
            return log.metadata.get(parts[1])
        
        return None
    
    def _extract_command(self, message: str) -> str:
        """
        Extract command from log message
        
        Args:
            message: Log message
            
        Returns:
            Extracted command or truncated message
        """
        if not message:
            return None
        
        # Try to extract command after common prefixes
        patterns = [
            r'COMMAND=(.+)',
            r'command:\s*(.+)',
            r'executed:\s*(.+)',
            r'sudo\s+(.+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:200]  # Limit to 200 chars
        
        # Return truncated message if no pattern matches
        return message[:200]
    
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
            alert_type=rule.get('category', 'privilege_abuse'),
            detection_method='privilege_abuse_detector',
            severity=severity,
            description=rule.get('description', rule.get('name', 'Privilege abuse detected')),
            metadata={
                'signature_id': rule.get('id'),
                'signature_name': rule.get('name'),
                'category': rule.get('category'),
                'command': self._extract_command(log.message or log.raw or "")
            },
            created_at=datetime.now(),
            user=log.get_user(),
            host=log.host
        )
    
    def reload_rules(self):
        """Reload rules from disk"""
        self.rules = []
        self._load_rules()
        logger.info("Rules reloaded", count=len(self.rules))
