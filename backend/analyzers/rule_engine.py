"""
Rule Engine
Evaluates custom correlation rules (Sigma-style rules)
"""
import structlog
import yaml
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


class RuleEngine:
    """
    Evaluates custom correlation rules
    Supports Sigma-style rule definitions
    """
    
    def __init__(self, rule_dir: str = "config/rules", db_manager=None):
        """
        Initialize rule engine
        
        Args:
            rule_dir: Directory containing rule YAML files
            db_manager: Optional database manager for rule storage
        """
        self.rule_dir = Path(rule_dir)
        self.db_manager = db_manager
        self.name = "rule_engine"
        self.rules: List[Dict[str, Any]] = []
        
        self._load_rules()
        
        logger.info("Rule engine initialized", rules_count=len(self.rules))
    
    def _load_rules(self):
        """Load rules from YAML files"""
        if not self.rule_dir.exists():
            logger.warning("Rule directory not found", path=str(self.rule_dir))
            self.rule_dir.mkdir(parents=True, exist_ok=True)
            return
        
        for rule_file in self.rule_dir.glob("*.yaml"):
            try:
                with open(rule_file, 'r') as f:
                    data = yaml.safe_load(f)
                
                if not data:
                    continue
                
                # Handle different rule file formats
                if 'rules' in data:
                    # Multiple rules in one file
                    for rule in data['rules']:
                        rule['file'] = rule_file.name
                        self.rules.append(rule)
                elif 'id' in data or 'name' in data:
                    # Single rule in file
                    data['file'] = rule_file.name
                    self.rules.append(data)
                
            except Exception as e:
                logger.error("Failed to load rule file", file=str(rule_file), error=str(e))
    
    async def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Evaluate rules against logs
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for matched rules
        """
        if not logs:
            return []
        
        logger.info("Starting rule evaluation", log_count=len(logs), rules_count=len(self.rules))
        alerts = []
        
        try:
            for rule in self.rules:
                if not rule.get('enabled', True):
                    continue
                
                rule_alerts = await self._evaluate_rule(logs, rule)
                alerts.extend(rule_alerts)
            
            logger.info("Rule evaluation completed", 
                       alerts_generated=len(alerts),
                       log_count=len(logs))
            
        except Exception as e:
            logger.error("Error in rule evaluation", error=str(e))
        
        return alerts
    
    async def _evaluate_rule(self, logs: List[LogEntry], rule: Dict[str, Any]) -> List[Alert]:
        """Evaluate a single rule against logs"""
        alerts = []
        
        try:
            logic = rule.get('logic', {})
            condition = logic.get('condition', 'selection')
            
            # Parse condition (e.g., "selection and count")
            conditions = condition.split(' and ')
            
            # Apply selection filter
            if 'selection' in logic:
                filtered_logs = self._apply_selection(logs, logic['selection'])
            else:
                filtered_logs = logs
            
            # Apply additional conditions
            for cond in conditions:
                if cond == 'selection':
                    continue
                elif cond == 'count':
                    if 'count' in logic:
                        filtered_logs = self._apply_count_condition(
                            filtered_logs, 
                            logic['count']
                        )
                elif cond == 'frequency':
                    if 'frequency' in logic:
                        filtered_logs = self._apply_frequency_condition(
                            filtered_logs,
                            logic['frequency']
                        )
            
            # Create alerts for matched logs
            if filtered_logs:
                for log in filtered_logs:
                    alert = self._create_rule_alert(log, rule)
                    alerts.append(alert)
        
        except Exception as e:
            logger.error("Error evaluating rule", rule_id=rule.get('id'), error=str(e))
        
        return alerts
    
    def _apply_selection(self, logs: List[LogEntry], selection: Dict[str, Any]) -> List[LogEntry]:
        """Filter logs based on selection criteria"""
        filtered = []
        
        for log in logs:
            if self._matches_selection(log, selection):
                filtered.append(log)
        
        return filtered
    
    def _matches_selection(self, log: LogEntry, selection: Dict[str, Any]) -> bool:
        """Check if log matches selection criteria"""
        for field, value in selection.items():
            log_value = self._get_field_value(log, field)
            
            if log_value is None:
                return False
            
            if isinstance(value, list):
                # Check if log value is in list
                if log_value not in value:
                    return False
            elif isinstance(value, dict):
                # Handle nested conditions
                if 'not' in value:
                    if log_value == value['not']:
                        return False
                elif 'contains' in value:
                    if value['contains'] not in str(log_value).lower():
                        return False
                elif 'regex' in value:
                    import re
                    if not re.search(value['regex'], str(log_value), re.IGNORECASE):
                        return False
            else:
                # Exact match
                if str(log_value).lower() != str(value).lower():
                    return False
        
        return True
    
    def _get_field_value(self, log: LogEntry, field: str) -> Any:
        """Extract field value from log"""
        # Handle nested fields (e.g., "normalized.source_ip")
        if '.' in field:
            parts = field.split('.')
            value = log
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                elif hasattr(value, part):
                    value = getattr(value, part)
                else:
                    return None
            return value
        
        # Direct field access
        if hasattr(log, field):
            return getattr(log, field)
        
        # Check normalized fields
        if log.normalized and field in log.normalized:
            return log.normalized[field]
        
        # Check metadata
        if hasattr(log, 'metadata') and log.metadata and field in log.metadata:
            return log.metadata[field]
        
        # Special field handlers
        if field == 'source_ip':
            return log.get_source_ip()
        elif field == 'user':
            return log.get_user()
        elif field == 'event_type':
            # Try to infer event type from message
            message_lower = (log.message or '').lower()
            if 'login' in message_lower:
                if 'failed' in message_lower:
                    return 'login_failed'
                return 'login_success'
            elif 'error' in message_lower:
                return 'error'
            elif 'access' in message_lower:
                return 'access'
            return 'unknown'
        
        return None
    
    def _apply_count_condition(
        self, 
        logs: List[LogEntry], 
        count_config: Dict[str, Any]
    ) -> List[LogEntry]:
        """Apply count condition (e.g., count > threshold)"""
        field = count_config.get('field')
        threshold = count_config.get('threshold', 0)
        timeframe = count_config.get('timeframe', '5m')
        
        if not field:
            return logs
        
        # Parse timeframe
        window = self._parse_timeframe(timeframe)
        
        # Group logs by field value
        by_value = defaultdict(list)
        
        for log in logs:
            value = self._get_field_value(log, field)
            if value:
                by_value[value].append(log)
        
        # Filter groups that meet threshold
        filtered = []
        now = datetime.now()
        
        for value, value_logs in by_value.items():
            # Count logs within timeframe
            recent_logs = [
                log for log in value_logs
                if log.get_timestamp() and (now - log.get_timestamp()) <= window
            ]
            
            if len(recent_logs) >= threshold:
                filtered.extend(recent_logs)
        
        return filtered
    
    def _apply_frequency_condition(
        self,
        logs: List[LogEntry],
        frequency_config: Dict[str, Any]
    ) -> List[LogEntry]:
        """Apply frequency condition"""
        field = frequency_config.get('field')
        min_connections = frequency_config.get('min_connections', 0)
        timeframe = frequency_config.get('timeframe', '10m')
        
        if not field:
            return logs
        
        window = self._parse_timeframe(timeframe)
        
        # Group by field value
        by_value = defaultdict(list)
        
        for log in logs:
            value = self._get_field_value(log, field)
            if value:
                by_value[value].append(log)
        
        # Filter groups that meet frequency threshold
        filtered = []
        now = datetime.now()
        
        for value, value_logs in by_value.items():
            recent_logs = [
                log for log in value_logs
                if log.get_timestamp() and (now - log.get_timestamp()) <= window
            ]
            
            if len(recent_logs) >= min_connections:
                filtered.extend(recent_logs)
        
        return filtered
    
    def _parse_timeframe(self, timeframe: str) -> timedelta:
        """Parse timeframe string (e.g., '5m', '1h', '24h')"""
        timeframe = timeframe.lower().strip()
        
        if timeframe.endswith('m'):
            minutes = int(timeframe[:-1])
            return timedelta(minutes=minutes)
        elif timeframe.endswith('h'):
            hours = int(timeframe[:-1])
            return timedelta(hours=hours)
        elif timeframe.endswith('d'):
            days = int(timeframe[:-1])
            return timedelta(days=days)
        else:
            # Default to minutes
            return timedelta(minutes=int(timeframe))
    
    def _create_rule_alert(self, log: LogEntry, rule: Dict[str, Any]) -> Alert:
        """Create alert from matched rule"""
        mitre_info = rule.get('mitre_attack', {})
        technique = mitre_info.get('technique', '')
        tactic = mitre_info.get('tactic', '')
        
        description = rule.get('description', rule.get('name', 'Rule matched'))
        if technique:
            description = f"[{technique}] {description}"
        
        return Alert(
            id=str(uuid.uuid4()),
            log_id=log.id,
            alert_type=rule.get('name', 'rule_match'),
            detection_method='rule_engine',
            severity=self._parse_severity(rule.get('severity', 'medium')),
            description=description,
            metadata={
                'rule_id': rule.get('id'),
                'rule_name': rule.get('name'),
                'rule_file': rule.get('file'),
                'mitre_technique': technique,
                'mitre_tactic': tactic,
                'logic': rule.get('logic', {})
            },
            source_ip=log.get_source_ip(),
            user=log.get_user(),
            host=log.host
        )
    
    def _parse_severity(self, severity: str) -> str:
        """Parse severity string to Severity enum"""
        severity_lower = severity.lower()
        if severity_lower in ['critical', 'high', 'medium', 'low', 'info']:
            return severity_lower
        return Severity.MEDIUM
