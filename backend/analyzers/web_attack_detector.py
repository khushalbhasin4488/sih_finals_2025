"""
Web Attack Detector
Detects web application attacks through pattern matching in HTTP requests

Focus: SQL injection, XSS, path traversal, command injection
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


class WebAttackDetector:
    """
    Detects web application attacks using:
    - Pattern matching in URLs and payloads
    - Signature-based detection
    - Context-aware analysis of HTTP requests
    """
    
    def __init__(self, rules_file: str = "config/signatures/web_attacks.yaml"):
        """
        Initialize web attack detector
        
        Args:
            rules_file: Path to YAML file with web attack signatures
        """
        self.rules_file = Path(rules_file)
        self.rules = []
        self.attack_categories = {
            'sql_injection': [],
            'xss': [],
            'path_traversal': [],
            'command_injection': []
        }
        
        self._load_rules()
        self._categorize_rules()
        logger.info("WebAttackDetector initialized", rules_count=len(self.rules))
    
    def _load_rules(self):
        """Load web attack signatures from YAML"""
        if not self.rules_file.exists():
            logger.warning("Rules file not found", file=str(self.rules_file))
            return
        
        try:
            with open(self.rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if data and 'signatures' in data:
                self.rules = data['signatures']
                logger.info("Loaded web attack rules", count=len(self.rules))
        except Exception as e:
            logger.error("Error loading rules", error=str(e), file=str(self.rules_file))
    
    def _categorize_rules(self):
        """Categorize rules by attack type for efficient processing"""
        for rule in self.rules:
            category = rule.get('category', '').lower()
            
            if 'sql' in category or 'injection' in rule.get('name', '').lower():
                self.attack_categories['sql_injection'].append(rule)
            elif 'xss' in category or 'script' in rule.get('name', '').lower():
                self.attack_categories['xss'].append(rule)
            elif 'path' in category or 'traversal' in category:
                self.attack_categories['path_traversal'].append(rule)
            elif 'command' in category:
                self.attack_categories['command_injection'].append(rule)
    
    def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs for web attacks
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for detected web attacks
        """
        alerts = []
        
        # Filter for web logs (nginx, apache, etc.)
        web_logs = [
            log for log in logs 
            if log.source_type == 'web' or log.appname in ['nginx', 'apache', 'httpd']
        ]
        
        logger.info("Analyzing web logs", total_logs=len(logs), web_logs=len(web_logs))
        
        for log in web_logs:
            # Check against all signature categories
            log_alerts = self._check_all_signatures(log)
            alerts.extend(log_alerts)
        
        logger.info(
            "Web attack analysis complete",
            logs_analyzed=len(web_logs),
            alerts_generated=len(alerts)
        )
        
        return alerts
    
    def _check_all_signatures(self, log: LogEntry) -> List[Alert]:
        """
        Check log against all web attack signatures
        
        Args:
            log: Log entry to check
            
        Returns:
            List of alerts (usually 0 or 1 to avoid duplicates)
        """
        alerts = []
        
        # Check each category in priority order
        # SQL injection is highest priority
        for category in ['sql_injection', 'command_injection', 'path_traversal', 'xss']:
            category_rules = self.attack_categories.get(category, [])
            
            for rule in category_rules:
                if self._matches_signature(log, rule):
                    alert = self._create_alert(log, rule)
                    alerts.append(alert)
                    # Return after first match to avoid duplicate alerts
                    return alerts
        
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
        
        # Get fields to check (default to message and raw)
        fields = rule.get('fields', ['message', 'raw'])
        
        # Extract searchable content from log
        searchable_content = self._extract_searchable_content(log, fields)
        
        # Check if ANY pattern matches
        for pattern_def in patterns:
            if isinstance(pattern_def, dict):
                pattern = pattern_def.get('regex', '')
            else:
                pattern = pattern_def
            
            if not pattern:
                continue
            
            # Check pattern against all searchable content
            for content in searchable_content:
                if content and re.search(pattern, str(content)):
                    return True
        
        return False
    
    def _extract_searchable_content(self, log: LogEntry, fields: List[str]) -> List[str]:
        """
        Extract all searchable content from log based on field list
        
        Args:
            log: Log entry
            fields: List of field paths to extract
            
        Returns:
            List of string values to search
        """
        content = []
        
        for field_path in fields:
            value = self._extract_field(log, field_path)
            if value:
                content.append(str(value))
        
        # Also extract URL parameters from message if it's a web log
        if log.message:
            content.append(log.message)
            
            # Try to extract query string from common web log formats
            # Example: "GET /search?q=<script> HTTP/1.1"
            url_match = re.search(r'["\s](GET|POST|PUT|DELETE)\s+([^\s]+)', log.message)
            if url_match:
                url = url_match.group(2)
                content.append(url)
                
                # Extract query string if present
                if '?' in url:
                    query_string = url.split('?', 1)[1]
                    content.append(query_string)
        
        return content
    
    def _extract_field(self, log: LogEntry, field_path: str) -> Any:
        """
        Extract field value from log using dot notation
        
        Args:
            log: Log entry
            field_path: Field path (e.g., 'message', 'normalized.query_string')
            
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
        
        # Extract attack payload from message for context
        attack_payload = None
        if log.message:
            # Try to extract the malicious part
            for pattern in rule.get('patterns', []):
                if isinstance(pattern, dict):
                    regex = pattern.get('regex', '')
                else:
                    regex = pattern
                
                match = re.search(regex, log.message)
                if match:
                    attack_payload = match.group(0)[:200]  # Limit to 200 chars
                    break
        
        metadata = {
            'signature_id': rule.get('id'),
            'signature_name': rule.get('name'),
            'category': rule.get('category'),
            'attack_payload': attack_payload
        }
        
        return Alert(
            id=str(uuid.uuid4()),
            log_id=log.id,
            alert_type=rule.get('category', 'web_attack'),
            detection_method='web_attack_detector',
            severity=severity,
            description=rule.get('description', rule.get('name', 'Web attack detected')),
            metadata=metadata,
            created_at=datetime.now(),
            source_ip=log.get_source_ip(),
            host=log.host
        )
    
    def reload_rules(self):
        """Reload rules from disk"""
        self.rules = []
        self.attack_categories = {
            'sql_injection': [],
            'xss': [],
            'path_traversal': [],
            'command_injection': []
        }
        self._load_rules()
        self._categorize_rules()
        logger.info("Rules reloaded", count=len(self.rules))
