"""
Signature-Based Detection Engine
Matches logs against known attack patterns using regex, YARA-style rules, and hash-based detection
"""
import re
import hashlib
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
import structlog
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


class SignatureDetector:
    """
    Signature-based detection using pattern matching, YARA-style rules, and hash-based detection
    """
    
    def __init__(self, signature_dir: str = "config/signatures", blocked_ips_file: str = "config/blocked_ips.txt"):
        """
        Initialize signature detector
        
        Args:
            signature_dir: Directory containing signature YAML files
            blocked_ips_file: Path to file containing blocked/malicious IPs
        """
        self.signature_dir = Path(signature_dir)
        self.blocked_ips_file = Path(blocked_ips_file)
        
        # Load signatures
        self.signatures: List[Dict[str, Any]] = []
        self.compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self.hash_signatures: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Set[str] = set()
        
        self._load_all_signatures()
        self._load_blocked_ips()
        
        logger.info(
            "Signature detector initialized",
            total_signatures=len(self.signatures),
            hash_signatures=len(self.hash_signatures),
            blocked_ips=len(self.blocked_ips)
        )
    
    def _load_all_signatures(self):
        """Load all signature files from directory"""
        if not self.signature_dir.exists():
            logger.warning("Signature directory not found", path=str(self.signature_dir))
            self.signature_dir.mkdir(parents=True, exist_ok=True)
            return
        
        for signature_file in self.signature_dir.glob("*.yaml"):
            try:
                self._load_signature_file(signature_file)
            except Exception as e:
                logger.error("Failed to load signature file", file=str(signature_file), error=str(e))
    
    def _load_signature_file(self, file_path: Path):
        """Load signatures from a YAML file"""
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
        
        if not data or 'signatures' not in data:
            return
        
        for sig in data['signatures']:
            # Add signature
            self.signatures.append(sig)
            
            # Compile regex patterns for performance
            sig_id = sig['id']
            self.compiled_patterns[sig_id] = []
            
            for pattern in sig.get('patterns', []):
                if 'regex' in pattern:
                    try:
                        compiled = re.compile(pattern['regex'], re.IGNORECASE | re.MULTILINE)
                        self.compiled_patterns[sig_id].append(compiled)
                    except re.error as e:
                        logger.error("Invalid regex pattern", signature=sig_id, error=str(e))
            
            # Load hash signatures
            if 'hashes' in sig:
                for hash_entry in sig['hashes']:
                    hash_value = hash_entry['value'].lower()
                    self.hash_signatures[hash_value] = {
                        'signature_id': sig_id,
                        'name': sig['name'],
                        'severity': sig.get('severity', 'medium'),
                        'hash_type': hash_entry.get('type', 'md5'),
                        'description': hash_entry.get('description', sig.get('description', ''))
                    }
        
        logger.info("Loaded signatures from file", file=file_path.name, count=len(data['signatures']))
    
    def _load_blocked_ips(self):
        """Load blocked/malicious IPs from file"""
        if not self.blocked_ips_file.exists():
            logger.warning("Blocked IPs file not found", path=str(self.blocked_ips_file))
            # Create empty file
            self.blocked_ips_file.parent.mkdir(parents=True, exist_ok=True)
            self.blocked_ips_file.touch()
            return
        
        try:
            with open(self.blocked_ips_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        self.blocked_ips.add(line)
            
            logger.info("Loaded blocked IPs", count=len(self.blocked_ips))
        except Exception as e:
            logger.error("Failed to load blocked IPs", error=str(e))
    
    async def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs for signature matches
        
        Args:
            logs: List of log entries to analyze
        
        Returns:
            List of alerts generated from signature matches
        """
        alerts = []
        
        for log in logs:
            # Check each signature
            for signature in self.signatures:
                if self._match_signature(log, signature):
                    alert = self._create_alert(log, signature)
                    alerts.append(alert)
            
            # Check blocked IPs
            blocked_ip_alert = self._check_blocked_ips(log)
            if blocked_ip_alert:
                alerts.append(blocked_ip_alert)
            
            # Check hash signatures
            hash_alert = self._check_hash_signatures(log)
            if hash_alert:
                alerts.append(hash_alert)
        
        if alerts:
            logger.info("Signature detection completed", logs_analyzed=len(logs), alerts_generated=len(alerts))
        
        return alerts
    
    def _match_signature(self, log: LogEntry, signature: Dict[str, Any]) -> bool:
        """
        Check if log matches a signature
        
        Args:
            log: Log entry to check
            signature: Signature definition
        
        Returns:
            True if log matches signature
        """
        sig_id = signature['id']
        fields_to_check = signature.get('fields', ['raw', 'message'])
        
        # Get compiled patterns for this signature
        patterns = self.compiled_patterns.get(sig_id, [])
        
        if not patterns:
            return False
        
        # Check each field
        for field_path in fields_to_check:
            field_value = self._extract_field(log, field_path)
            
            if not field_value:
                continue
            
            # Check if any pattern matches
            for pattern in patterns:
                if pattern.search(str(field_value)):
                    logger.debug(
                        "Signature match found",
                        signature_id=sig_id,
                        field=field_path,
                        log_id=log.id
                    )
                    return True
        
        return False
    
    def _extract_field(self, log: LogEntry, field_path: str) -> Optional[str]:
        """
        Extract field value from log using dot notation
        
        Args:
            log: Log entry
            field_path: Field path (e.g., 'message', 'normalized.user', 'raw')
        
        Returns:
            Field value or None
        """
        # Handle direct attributes
        if field_path == 'raw':
            return log.raw
        elif field_path == 'message':
            return log.message
        elif field_path == 'appname':
            return log.appname
        
        # Handle nested fields (e.g., 'normalized.user')
        if '.' in field_path:
            parts = field_path.split('.')
            
            if parts[0] == 'normalized' and log.normalized:
                value = log.normalized
                for part in parts[1:]:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        return None
                return str(value) if value is not None else None
            
            if parts[0] == 'metadata' and log.metadata:
                value = log.metadata
                for part in parts[1:]:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        return None
                return str(value) if value is not None else None
        
        return None
    
    def _check_blocked_ips(self, log: LogEntry) -> Optional[Alert]:
        """
        Check if log contains blocked/malicious IPs
        
        Args:
            log: Log entry to check
        
        Returns:
            Alert if blocked IP found, None otherwise
        """
        if not self.blocked_ips:
            return None
        
        # Extract source IP
        source_ip = log.get_source_ip()
        
        if source_ip and source_ip in self.blocked_ips:
            return Alert(
                id=str(uuid.uuid4()),
                log_id=log.id,
                alert_type="blocked_ip_detected",
                detection_method="signature_detector",
                severity=Severity.HIGH,
                description=f"Connection from blocked IP address: {source_ip}",
                metadata={
                    "source_ip": source_ip,
                    "host": log.host,
                    "appname": log.appname,
                    "message": log.message[:200] if log.message else None
                },
                created_at=datetime.now(),
                source_ip=source_ip,
                host=log.host
            )
        
        return None
    
    def _check_hash_signatures(self, log: LogEntry) -> Optional[Alert]:
        """
        Check if log contains known malicious file hashes
        
        Args:
            log: Log entry to check
        
        Returns:
            Alert if malicious hash found, None otherwise
        """
        if not self.hash_signatures:
            return None
        
        # Extract potential hashes from log message and normalized fields
        potential_hashes = []
        
        if log.message:
            # Look for MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
            potential_hashes.extend(re.findall(r'\b[a-fA-F0-9]{32}\b', log.message))
            potential_hashes.extend(re.findall(r'\b[a-fA-F0-9]{40}\b', log.message))
            potential_hashes.extend(re.findall(r'\b[a-fA-F0-9]{64}\b', log.message))
        
        if log.normalized:
            for key in ['file_hash', 'hash', 'md5', 'sha1', 'sha256']:
                if key in log.normalized:
                    potential_hashes.append(str(log.normalized[key]))
        
        # Check against known malicious hashes
        for hash_value in potential_hashes:
            hash_lower = hash_value.lower()
            if hash_lower in self.hash_signatures:
                sig_info = self.hash_signatures[hash_lower]
                return Alert(
                    id=str(uuid.uuid4()),
                    log_id=log.id,
                    alert_type="malicious_hash_detected",
                    detection_method="signature_detector",
                    severity=sig_info['severity'],
                    description=f"Malicious file hash detected: {sig_info['name']}",
                    metadata={
                        "hash_value": hash_value,
                        "hash_type": sig_info['hash_type'],
                        "signature_id": sig_info['signature_id'],
                        "description": sig_info['description'],
                        "host": log.host,
                        "appname": log.appname
                    },
                    created_at=datetime.now(),
                    host=log.host
                )
        
        return None
    
    def _create_alert(self, log: LogEntry, signature: Dict[str, Any]) -> Alert:
        """
        Create alert from signature match
        
        Args:
            log: Matched log entry
            signature: Matched signature
        
        Returns:
            Alert object
        """
        return Alert(
            id=str(uuid.uuid4()),
            log_id=log.id,
            alert_type=signature.get('category', 'signature_match'),
            detection_method="signature_detector",
            severity=signature.get('severity', Severity.MEDIUM),
            description=f"{signature['name']}: {signature.get('description', '')}",
            metadata={
                "signature_id": signature['id'],
                "signature_name": signature['name'],
                "category": signature.get('category'),
                "host": log.host,
                "appname": log.appname,
                "message": log.message[:200] if log.message else None,
                "source_ip": log.get_source_ip(),
                "user": log.get_user()
            },
            created_at=datetime.now(),
            source_ip=log.get_source_ip(),
            user=log.get_user(),
            host=log.host
        )
    
    def reload_signatures(self):
        """Reload all signatures from disk"""
        self.signatures = []
        self.compiled_patterns = {}
        self.hash_signatures = {}
        self._load_all_signatures()
        logger.info("Signatures reloaded", total=len(self.signatures))
    
    def reload_blocked_ips(self):
        """Reload blocked IPs from disk"""
        self.blocked_ips = set()
        self._load_blocked_ips()
        logger.info("Blocked IPs reloaded", total=len(self.blocked_ips))
