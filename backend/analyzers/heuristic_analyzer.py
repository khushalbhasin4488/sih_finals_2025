"""
Heuristic Analyzer
Applies rule-of-thumb based detection for common attack patterns
"""
import structlog
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


# Heuristic rules configuration
HEURISTIC_RULES = [
    {
        'id': 'HEUR-001',
        'name': 'Multiple Failed Logins Followed by Success',
        'severity': Severity.HIGH,
        'description': 'Potential brute force attack - multiple failed logins followed by successful login',
        'window_minutes': 5,
        'min_failed': 5,
        'check_success': True
    },
    {
        'id': 'HEUR-002',
        'name': 'Privilege Escalation After Login',
        'severity': Severity.CRITICAL,
        'description': 'User gained elevated privileges shortly after login',
        'window_minutes': 10,
        'check_privilege': True
    },
    {
        'id': 'HEUR-003',
        'name': 'Lateral Movement Pattern',
        'severity': Severity.HIGH,
        'description': 'User accessing multiple systems in short time',
        'window_minutes': 15,
        'min_unique_hosts': 5
    },
    {
        'id': 'HEUR-004',
        'name': 'Data Exfiltration Indicator',
        'severity': Severity.CRITICAL,
        'description': 'Large data transfer to external IP',
        'window_minutes': 5,
        'min_bytes': 100000000  # 100MB
    },
    {
        'id': 'HEUR-005',
        'name': 'Off-Hours Activity',
        'severity': Severity.MEDIUM,
        'description': 'Unusual activity during off-hours (22:00-06:00)',
        'check_time': True,
        'off_hours_start': 22,
        'off_hours_end': 6
    },
    {
        'id': 'HEUR-006',
        'name': 'Rapid File Access',
        'severity': Severity.MEDIUM,
        'description': 'Rapid access to multiple files',
        'window_minutes': 5,
        'min_file_access': 20
    },
    {
        'id': 'HEUR-007',
        'name': 'Suspicious Command Sequence',
        'severity': Severity.HIGH,
        'description': 'Suspicious sequence of commands executed',
        'window_minutes': 2,
        'suspicious_commands': ['rm -rf', 'chmod 777', 'wget', 'curl', 'nc ', 'netcat']
    }
]


class HeuristicAnalyzer:
    """
    Heuristic-based detection using rule-of-thumb patterns
    """
    
    def __init__(self, db_manager=None):
        """
        Initialize heuristic analyzer
        
        Args:
            db_manager: Optional database manager for historical queries
        """
        self.db_manager = db_manager
        self.name = "heuristic_analyzer"
        self.rules = HEURISTIC_RULES
        
        logger.info("Heuristic analyzer initialized", rules_count=len(self.rules))
    
    async def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs using heuristic rules
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for detected patterns
        """
        if not logs:
            return []
        
        logger.info("Starting heuristic analysis", log_count=len(logs))
        alerts = []
        
        try:
            # Evaluate each heuristic rule
            for rule in self.rules:
                rule_alerts = await self._evaluate_rule(logs, rule)
                alerts.extend(rule_alerts)
            
            logger.info("Heuristic analysis completed", 
                       alerts_generated=len(alerts),
                       log_count=len(logs))
            
        except Exception as e:
            logger.error("Error in heuristic analysis", error=str(e))
        
        return alerts
    
    async def _evaluate_rule(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Evaluate a heuristic rule against logs"""
        alerts = []
        rule_id = rule['id']
        
        try:
            if rule_id == 'HEUR-001':
                alerts.extend(self._detect_brute_force_pattern(logs, rule))
            elif rule_id == 'HEUR-002':
                alerts.extend(self._detect_privilege_escalation(logs, rule))
            elif rule_id == 'HEUR-003':
                alerts.extend(self._detect_lateral_movement(logs, rule))
            elif rule_id == 'HEUR-004':
                alerts.extend(self._detect_data_exfiltration(logs, rule))
            elif rule_id == 'HEUR-005':
                alerts.extend(self._detect_off_hours_activity(logs, rule))
            elif rule_id == 'HEUR-006':
                alerts.extend(self._detect_rapid_file_access(logs, rule))
            elif rule_id == 'HEUR-007':
                alerts.extend(self._detect_suspicious_commands(logs, rule))
        except Exception as e:
            logger.error("Error evaluating rule", rule_id=rule_id, error=str(e))
        
        return alerts
    
    def _detect_brute_force_pattern(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Detect brute force pattern: multiple failed logins followed by success"""
        alerts = []
        window = timedelta(minutes=rule.get('window_minutes', 5))
        min_failed = rule.get('min_failed', 5)
        
        # Group logs by source IP and user
        by_key = defaultdict(list)
        
        for log in logs:
            source_ip = log.get_source_ip()
            user = log.get_user()
            if source_ip or user:
                key = (source_ip or 'unknown', user or 'unknown')
                by_key[key].append(log)
        
        for (source_ip, user), group_logs in by_key.items():
            # Sort by timestamp
            sorted_logs = sorted(
                group_logs,
                key=lambda x: x.get_timestamp() or datetime.now()
            )
            
            failed_count = 0
            failed_times = []
            success_time = None
            
            for log in sorted_logs:
                if not log.message:
                    continue
                
                message_lower = log.message.lower()
                log_time = log.get_timestamp() or datetime.now()
                
                # Check for failed login
                if 'failed' in message_lower and ('login' in message_lower or 'password' in message_lower):
                    failed_count += 1
                    failed_times.append(log_time)
                
                # Check for successful login
                if ('accepted' in message_lower or 'successful' in message_lower) and 'login' in message_lower:
                    if failed_count >= min_failed:
                        # Check if success is within window of last failure
                        if failed_times and (log_time - failed_times[-1]) <= window:
                            alert = Alert(
                                id=str(uuid.uuid4()),
                                log_id=log.id,
                                alert_type='brute_force_success',
                                detection_method='heuristic_analyzer',
                                severity=rule['severity'],
                                description=f"Brute force attack detected: {failed_count} failed logins followed by successful login",
                                metadata={
                                    'rule_id': rule['id'],
                                    'rule_name': rule['name'],
                                    'source_ip': source_ip,
                                    'user': user,
                                    'failed_count': failed_count,
                                    'window_minutes': rule.get('window_minutes', 5)
                                },
                                source_ip=source_ip,
                                user=user,
                                host=log.host
                            )
                            alerts.append(alert)
                            break
                    # Reset after success
                    failed_count = 0
                    failed_times = []
        
        return alerts
    
    def _detect_privilege_escalation(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Detect privilege escalation after login"""
        alerts = []
        window = timedelta(minutes=rule.get('window_minutes', 10))
        
        # Group by user
        by_user = defaultdict(list)
        
        for log in logs:
            user = log.get_user()
            if user:
                by_user[user].append(log)
        
        for user, user_logs in by_user.items():
            sorted_logs = sorted(
                user_logs,
                key=lambda x: x.get_timestamp() or datetime.now()
            )
            
            login_time = None
            
            for log in sorted_logs:
                if not log.message:
                    continue
                
                message_lower = log.message.lower()
                log_time = log.get_timestamp() or datetime.now()
                
                # Check for login
                if ('accepted' in message_lower or 'login' in message_lower) and login_time is None:
                    login_time = log_time
                
                # Check for privilege escalation indicators
                if login_time and (log_time - login_time) <= window:
                    if any(keyword in message_lower for keyword in ['sudo', 'su ', 'runas', 'elevated', 'privilege', 'admin']):
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            log_id=log.id,
                            alert_type='privilege_escalation',
                            detection_method='heuristic_analyzer',
                            severity=rule['severity'],
                            description=f"Privilege escalation detected shortly after login",
                            metadata={
                                'rule_id': rule['id'],
                                'rule_name': rule['name'],
                                'user': user,
                                'time_since_login': (log_time - login_time).total_seconds(),
                                'window_minutes': rule.get('window_minutes', 10)
                            },
                            user=user,
                            host=log.host
                        )
                        alerts.append(alert)
                        login_time = None  # Reset to avoid duplicate alerts
        
        return alerts
    
    def _detect_lateral_movement(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Detect lateral movement: accessing multiple hosts"""
        alerts = []
        window = timedelta(minutes=rule.get('window_minutes', 15))
        min_hosts = rule.get('min_unique_hosts', 5)
        
        # Group by source IP and user
        by_key = defaultdict(lambda: {'hosts': set(), 'logs': []})
        
        for log in logs:
            source_ip = log.get_source_ip()
            user = log.get_user()
            if source_ip or user:
                key = (source_ip or 'unknown', user or 'unknown')
                by_key[key]['logs'].append(log)
                if log.host:
                    by_key[key]['hosts'].add(log.host)
        
        for (source_ip, user), data in by_key.items():
            if len(data['hosts']) >= min_hosts:
                # Check if all accesses are within window
                sorted_logs = sorted(
                    data['logs'],
                    key=lambda x: x.get_timestamp() or datetime.now()
                )
                
                if sorted_logs:
                    first_time = sorted_logs[0].get_timestamp() or datetime.now()
                    last_time = sorted_logs[-1].get_timestamp() or datetime.now()
                    
                    if (last_time - first_time) <= window:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            log_id=sorted_logs[0].id,
                            alert_type='lateral_movement',
                            detection_method='heuristic_analyzer',
                            severity=rule['severity'],
                            description=f"Lateral movement detected: accessed {len(data['hosts'])} hosts in {rule.get('window_minutes', 15)} minutes",
                            metadata={
                                'rule_id': rule['id'],
                                'rule_name': rule['name'],
                                'source_ip': source_ip,
                                'user': user,
                                'unique_hosts': len(data['hosts']),
                                'hosts': list(data['hosts']),
                                'window_minutes': rule.get('window_minutes', 15)
                            },
                            source_ip=source_ip,
                            user=user
                        )
                        alerts.append(alert)
        
        return alerts
    
    def _detect_data_exfiltration(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Detect large data transfers (potential exfiltration)"""
        alerts = []
        window = timedelta(minutes=rule.get('window_minutes', 5))
        min_bytes = rule.get('min_bytes', 100000000)
        
        # Group by source IP
        by_source = defaultdict(lambda: {'bytes': 0, 'logs': []})
        
        for log in logs:
            source_ip = log.get_source_ip()
            if not source_ip:
                continue
            
            # Try to extract bytes from normalized fields or message
            bytes_transferred = 0
            if log.normalized and 'bytes' in log.normalized:
                bytes_transferred = int(log.normalized.get('bytes', 0))
            elif log.message:
                # Try to extract from message
                import re
                byte_match = re.search(r'(\d+)\s*(?:bytes|KB|MB|GB)', log.message, re.IGNORECASE)
                if byte_match:
                    bytes_transferred = int(byte_match.group(1))
            
            if bytes_transferred > 0:
                by_source[source_ip]['bytes'] += bytes_transferred
                by_source[source_ip]['logs'].append(log)
        
        for source_ip, data in by_source.items():
            if data['bytes'] >= min_bytes:
                # Check if transfers are within window
                sorted_logs = sorted(
                    data['logs'],
                    key=lambda x: x.get_timestamp() or datetime.now()
                )
                
                if sorted_logs:
                    first_time = sorted_logs[0].get_timestamp() or datetime.now()
                    last_time = sorted_logs[-1].get_timestamp() or datetime.now()
                    
                    if (last_time - first_time) <= window:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            log_id=sorted_logs[0].id,
                            alert_type='data_exfiltration',
                            detection_method='heuristic_analyzer',
                            severity=rule['severity'],
                            description=f"Large data transfer detected: {data['bytes']:,} bytes",
                            metadata={
                                'rule_id': rule['id'],
                                'rule_name': rule['name'],
                                'source_ip': source_ip,
                                'bytes_transferred': data['bytes'],
                                'window_minutes': rule.get('window_minutes', 5)
                            },
                            source_ip=source_ip
                        )
                        alerts.append(alert)
        
        return alerts
    
    def _detect_off_hours_activity(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Detect activity during off-hours"""
        alerts = []
        start_hour = rule.get('off_hours_start', 22)
        end_hour = rule.get('off_hours_end', 6)
        
        for log in logs:
            log_time = log.get_timestamp()
            if not log_time:
                continue
            
            hour = log_time.hour
            
            # Check if in off-hours (22:00-06:00)
            is_off_hours = hour >= start_hour or hour < end_hour
            
            if is_off_hours:
                # Check for suspicious activity
                message_lower = (log.message or '').lower()
                if any(keyword in message_lower for keyword in ['login', 'access', 'file', 'command', 'execute']):
                    user = log.get_user()
                    source_ip = log.get_source_ip()
                    
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        log_id=log.id,
                        alert_type='off_hours_activity',
                        detection_method='heuristic_analyzer',
                        severity=rule['severity'],
                        description=f"Activity detected during off-hours ({hour:02d}:00)",
                        metadata={
                            'rule_id': rule['id'],
                            'rule_name': rule['name'],
                            'hour': hour,
                            'off_hours_start': start_hour,
                            'off_hours_end': end_hour
                        },
                        user=user,
                        source_ip=source_ip,
                        host=log.host
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_rapid_file_access(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Detect rapid file access pattern"""
        alerts = []
        window = timedelta(minutes=rule.get('window_minutes', 5))
        min_access = rule.get('min_file_access', 20)
        
        # Group by source IP and user
        by_key = defaultdict(list)
        
        for log in logs:
            source_ip = log.get_source_ip()
            user = log.get_user()
            message_lower = (log.message or '').lower()
            
            if any(keyword in message_lower for keyword in ['file', 'open', 'read', 'write', 'access']):
                key = (source_ip or 'unknown', user or 'unknown')
                by_key[key].append(log)
        
        for (source_ip, user), file_logs in by_key.items():
            if len(file_logs) >= min_access:
                sorted_logs = sorted(
                    file_logs,
                    key=lambda x: x.get_timestamp() or datetime.now()
                )
                
                first_time = sorted_logs[0].get_timestamp() or datetime.now()
                last_time = sorted_logs[-1].get_timestamp() or datetime.now()
                
                if (last_time - first_time) <= window:
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        log_id=sorted_logs[0].id,
                        alert_type='rapid_file_access',
                        detection_method='heuristic_analyzer',
                        severity=rule['severity'],
                        description=f"Rapid file access detected: {len(file_logs)} accesses in {rule.get('window_minutes', 5)} minutes",
                        metadata={
                            'rule_id': rule['id'],
                            'rule_name': rule['name'],
                            'source_ip': source_ip,
                            'user': user,
                            'file_access_count': len(file_logs),
                            'window_minutes': rule.get('window_minutes', 5)
                        },
                        source_ip=source_ip,
                        user=user
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_suspicious_commands(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Detect suspicious command sequences"""
        alerts = []
        window = timedelta(minutes=rule.get('window_minutes', 2))
        suspicious_commands = rule.get('suspicious_commands', [])
        
        # Group by source IP and user
        by_key = defaultdict(list)
        
        for log in logs:
            source_ip = log.get_source_ip()
            user = log.get_user()
            message = log.message or log.raw or ''
            
            if any(cmd in message for cmd in suspicious_commands):
                key = (source_ip or 'unknown', user or 'unknown')
                by_key[key].append(log)
        
        for (source_ip, user), cmd_logs in by_key.items():
            if len(cmd_logs) >= 2:  # At least 2 suspicious commands
                sorted_logs = sorted(
                    cmd_logs,
                    key=lambda x: x.get_timestamp() or datetime.now()
                )
                
                first_time = sorted_logs[0].get_timestamp() or datetime.now()
                last_time = sorted_logs[-1].get_timestamp() or datetime.now()
                
                if (last_time - first_time) <= window:
                    commands_found = []
                    for log in sorted_logs:
                        message = log.message or log.raw or ''
                        for cmd in suspicious_commands:
                            if cmd in message:
                                commands_found.append(cmd)
                                break
                    
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        log_id=sorted_logs[0].id,
                        alert_type='suspicious_command_sequence',
                        detection_method='heuristic_analyzer',
                        severity=rule['severity'],
                        description=f"Suspicious command sequence detected: {', '.join(set(commands_found))}",
                        metadata={
                            'rule_id': rule['id'],
                            'rule_name': rule['name'],
                            'source_ip': source_ip,
                            'user': user,
                            'commands': list(set(commands_found)),
                            'command_count': len(cmd_logs),
                            'window_minutes': rule.get('window_minutes', 2)
                        },
                        source_ip=source_ip,
                        user=user,
                        host=sorted_logs[0].host
                    )
                    alerts.append(alert)
        
        return alerts
