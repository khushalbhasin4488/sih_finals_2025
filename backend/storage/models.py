"""
Data models for the log analyzer tool
Flexible schema to handle various log formats from different services
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import json


class Severity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class LogEntry:
    """
    Flexible log entry model that can handle different log formats
    Maps to the actual log structure from the microservice
    """
    # Core fields (always present)
    id: Optional[str] = None
    timestamp: Optional[str] = None  # ISO format string
    raw: Optional[str] = None
    
    # Common fields (may vary by service)
    appname: Optional[str] = None
    file: Optional[str] = None
    host: Optional[str] = None
    hostname: Optional[str] = None
    message: Optional[str] = None
    procid: Optional[int] = None
    source_type: Optional[str] = None
    network_id: Optional[str] = None  # Network identifier for multi-tenant filtering
    
    # Normalized fields (structured data)
    normalized: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    # Additional metadata (catch-all for service-specific fields)
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    # Ingestion metadata
    ingestion_time: Optional[datetime] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        """
        Create LogEntry from dictionary
        Handles flexible schema from different log sources
        """
        # Extract known fields
        known_fields = {
            'id', 'timestamp', 'raw', 'appname', 'file', 'host', 
            'hostname', 'message', 'procid', 'source_type', 'normalized', 'network_id'
        }
        
        # Separate known fields from metadata
        known_data = {}
        metadata = {}
        
        for key, value in data.items():
            if key in known_fields:
                known_data[key] = value
            else:
                metadata[key] = value
        
        return cls(
            id=known_data.get('id'),
            timestamp=known_data.get('timestamp'),
            raw=known_data.get('raw'),
            appname=known_data.get('appname'),
            file=known_data.get('file'),
            host=known_data.get('host'),
            hostname=known_data.get('hostname'),
            message=known_data.get('message'),
            procid=known_data.get('procid'),
            source_type=known_data.get('source_type'),
            normalized=known_data.get('normalized', {}),
            metadata=metadata,
            ingestion_time=known_data.get('ingestion_time')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert LogEntry to dictionary"""
        result = {
            'id': self.id,
            'timestamp': self.timestamp,
            'raw': self.raw,
            'appname': self.appname,
            'file': self.file,
            'host': self.host,
            'hostname': self.hostname,
            'message': self.message,
            'procid': self.procid,
            'source_type': self.source_type,
            'normalized': self.normalized,
            'ingestion_time': self.ingestion_time
        }
        
        # Add metadata fields
        if self.metadata:
            result.update(self.metadata)
        
        return result
    
    def get_timestamp(self) -> Optional[datetime]:
        """
        Get timestamp as datetime object
        Handles multiple timestamp formats and locations
        """
        # Try main timestamp field
        if self.timestamp:
            try:
                return datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        # Try normalized timestamp
        if self.normalized and 'timestamp' in self.normalized:
            try:
                ts = self.normalized['timestamp']
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                pass
        
        return None
    
    def get_source_ip(self) -> Optional[str]:
        """Extract source IP from message or normalized fields"""
        # Check normalized fields first
        if self.normalized:
            if 'source_ip' in self.normalized:
                return self.normalized['source_ip']
            if 'src_ip' in self.normalized:
                return self.normalized['src_ip']
        
        # Try to extract from message (e.g., "from 159.223.208.40")
        if self.message:
            import re
            # Pattern for IPv4
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            matches = re.findall(ip_pattern, self.message)
            if matches:
                return matches[0]
        
        return None
    
    def get_user(self) -> Optional[str]:
        """Extract username from message or normalized fields"""
        if self.normalized and 'user' in self.normalized:
            return self.normalized['user']
        
        # Try to extract from message (e.g., "Invalid user admin")
        if self.message:
            import re
            user_patterns = [
                r'user\s+(\w+)',
                r'User\s+(\w+)',
                r'for\s+(\w+)',
            ]
            for pattern in user_patterns:
                match = re.search(pattern, self.message)
                if match:
                    return match.group(1)
        
        return None


@dataclass
class Alert:
    """Represents a security alert"""
    id: str
    log_id: Optional[str] = None
    alert_type: Optional[str] = None
    detection_method: Optional[str] = None
    severity: str = Severity.INFO
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    created_at: Optional[datetime] = field(default_factory=datetime.now)
    acknowledged: bool = False
    priority_score: float = 0.0
    
    # Related log information
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create Alert from dictionary"""
        return cls(
            id=data.get('id'),
            log_id=data.get('log_id'),
            alert_type=data.get('alert_type'),
            detection_method=data.get('detection_method'),
            severity=data.get('severity', Severity.INFO),
            description=data.get('description'),
            metadata=data.get('metadata', {}),
            created_at=data.get('created_at', datetime.now()),
            acknowledged=data.get('acknowledged', False),
            priority_score=data.get('priority_score', 0.0),
            source_ip=data.get('source_ip'),
            dest_ip=data.get('dest_ip'),
            user=data.get('user'),
            host=data.get('host')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Alert to dictionary"""
        return {
            'id': self.id,
            'log_id': self.log_id,
            'alert_type': self.alert_type,
            'detection_method': self.detection_method,
            'severity': self.severity,
            'description': self.description,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'acknowledged': self.acknowledged,
            'priority_score': self.priority_score,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'user': self.user,
            'host': self.host
        }


@dataclass
class ThreatIntel:
    """Represents a threat intelligence indicator"""
    id: str
    indicator_type: str  # ip, domain, hash, url, email
    indicator_value: str
    threat_type: Optional[str] = None
    confidence: float = 0.5
    source: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    created_at: Optional[datetime] = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatIntel':
        """Create ThreatIntel from dictionary"""
        return cls(
            id=data.get('id'),
            indicator_type=data.get('indicator_type'),
            indicator_value=data.get('indicator_value'),
            threat_type=data.get('threat_type'),
            confidence=data.get('confidence', 0.5),
            source=data.get('source'),
            metadata=data.get('metadata', {}),
            created_at=data.get('created_at', datetime.now()),
            expires_at=data.get('expires_at')
        )


@dataclass
class DetectionRule:
    """Represents a detection rule"""
    id: str
    rule_name: str
    rule_type: str
    rule_definition: Dict[str, Any]
    enabled: bool = True
    created_at: Optional[datetime] = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = field(default_factory=datetime.now)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DetectionRule':
        """Create DetectionRule from dictionary"""
        return cls(
            id=data.get('id'),
            rule_name=data.get('rule_name'),
            rule_type=data.get('rule_type'),
            rule_definition=data.get('rule_definition', {}),
            enabled=data.get('enabled', True),
            created_at=data.get('created_at', datetime.now()),
            updated_at=data.get('updated_at', datetime.now())
        )
