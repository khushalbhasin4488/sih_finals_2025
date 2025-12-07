"""
Threat Intelligence Matcher
Matches log indicators against threat intelligence feeds
"""
import structlog
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
import uuid
import re

from storage.models import LogEntry, Alert, Severity, ThreatIntel

logger = structlog.get_logger()


class ThreatIntelMatcher:
    """
    Matches indicators of compromise (IoC) against threat intelligence
    Supports IP addresses, domains, hashes, URLs, email addresses
    """
    
    def __init__(self, db_manager=None):
        """
        Initialize threat intel matcher
        
        Args:
            db_manager: Database manager for threat intel storage
        """
        self.db_manager = db_manager
        self.name = "threat_intel_matcher"
        self.threat_intel_cache: Dict[str, ThreatIntel] = {}
        
        # Load threat intel into cache
        self._load_threat_intel()
        
        logger.info("Threat intel matcher initialized", 
                   cached_indicators=len(self.threat_intel_cache))
    
    def _load_threat_intel(self):
        """Load threat intelligence from database"""
        if not self.db_manager:
            return
        
        try:
            # Fetch all active threat intel indicators
            threat_intels = self.db_manager.fetch_threat_intel()
            
            for ti in threat_intels:
                # Check if expired
                if ti.expires_at and ti.expires_at < datetime.now():
                    continue
                
                # Cache by indicator type and value
                cache_key = f"{ti.indicator_type}:{ti.indicator_value.lower()}"
                self.threat_intel_cache[cache_key] = ti
            
            logger.info("Loaded threat intel from database", count=len(self.threat_intel_cache))
        except Exception as e:
            logger.error("Error loading threat intel", error=str(e))
    
    async def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Match logs against threat intelligence
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for matched indicators
        """
        if not logs:
            return []
        
        logger.info("Starting threat intel matching", log_count=len(logs))
        alerts = []
        
        try:
            for log in logs:
                # Extract indicators from log
                indicators = self._extract_indicators(log)
                
                # Check each indicator against threat intel
                for indicator_type, indicator_value in indicators:
                    match = await self._check_threat_intel(indicator_type, indicator_value)
                    
                    if match:
                        alert = self._create_threat_intel_alert(
                            log,
                            indicator_type,
                            indicator_value,
                            match
                        )
                        alerts.append(alert)
            
            logger.info("Threat intel matching completed", 
                       alerts_generated=len(alerts),
                       log_count=len(logs))
            
        except Exception as e:
            logger.error("Error in threat intel matching", error=str(e))
        
        return alerts
    
    def _extract_indicators(self, log: LogEntry) -> List[Tuple[str, str]]:
        """Extract IoCs from log"""
        indicators = []
        
        # IP addresses
        source_ip = log.get_source_ip()
        if source_ip:
            indicators.append(('ip', source_ip))
        
        if log.normalized:
            if 'dest_ip' in log.normalized:
                indicators.append(('ip', log.normalized['dest_ip']))
            if 'source_ip' in log.normalized:
                indicators.append(('ip', log.normalized['source_ip']))
        
        # Domains
        if log.normalized and 'domain' in log.normalized:
            indicators.append(('domain', log.normalized['domain']))
        
        # Extract domains from message/raw
        message = log.message or log.raw or ''
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, message)
        for domain in domains:
            # Filter out common false positives
            if domain not in ['localhost', 'example.com', 'test.com']:
                indicators.append(('domain', domain.lower()))
        
        # URLs
        if log.normalized and 'url' in log.normalized:
            indicators.append(('url', log.normalized['url']))
        
        # Extract URLs from message
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, message)
        for url in urls:
            indicators.append(('url', url.lower()))
        
        # File hashes
        if log.normalized and 'file_hash' in log.normalized:
            hash_value = log.normalized['file_hash']
            # Determine hash type
            if len(hash_value) == 32:
                indicators.append(('hash', hash_value.lower()))
            elif len(hash_value) == 40:
                indicators.append(('hash', hash_value.lower()))
            elif len(hash_value) == 64:
                indicators.append(('hash', hash_value.lower()))
        
        # Extract hashes from message
        hash_patterns = [
            (r'\b([a-fA-F0-9]{32})\b', 'md5'),
            (r'\b([a-fA-F0-9]{40})\b', 'sha1'),
            (r'\b([a-fA-F0-9]{64})\b', 'sha256'),
        ]
        for pattern, hash_type in hash_patterns:
            matches = re.findall(pattern, message)
            for match in matches:
                indicators.append(('hash', match.lower()))
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, message)
        for email in emails:
            indicators.append(('email', email.lower()))
        
        return indicators
    
    async def _check_threat_intel(self, indicator_type: str, indicator_value: str) -> Optional[ThreatIntel]:
        """Check if indicator exists in threat intel database"""
        # Normalize indicator value
        indicator_value = indicator_value.lower().strip()
        
        # Check cache first
        cache_key = f"{indicator_type}:{indicator_value}"
        if cache_key in self.threat_intel_cache:
            ti = self.threat_intel_cache[cache_key]
            # Check if expired
            if ti.expires_at and ti.expires_at < datetime.now():
                del self.threat_intel_cache[cache_key]
                return None
            return ti
        
        # Query database if not in cache
        if self.db_manager:
            try:
                threat_intels = self.db_manager.fetch_threat_intel(
                    indicator_type=indicator_type,
                    indicator_value=indicator_value
                )
                
                for ti in threat_intels:
                    # Check if expired
                    if ti.expires_at and ti.expires_at < datetime.now():
                        continue
                    
                    # Cache result
                    self.threat_intel_cache[cache_key] = ti
                    return ti
            except Exception as e:
                logger.debug("Error querying threat intel", error=str(e))
        
        return None
    
    def _create_threat_intel_alert(
        self,
        log: LogEntry,
        indicator_type: str,
        indicator_value: str,
        threat_intel: ThreatIntel
    ) -> Alert:
        """Create alert from threat intel match"""
        threat_type = threat_intel.threat_type or 'unknown'
        confidence = threat_intel.confidence or 0.5
        
        # Determine severity based on confidence and threat type
        if confidence >= 0.8:
            severity = Severity.CRITICAL
        elif confidence >= 0.6:
            severity = Severity.HIGH
        elif confidence >= 0.4:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        description = f"Threat intelligence match: {indicator_type} {indicator_value} ({threat_type})"
        
        return Alert(
            id=str(uuid.uuid4()),
            log_id=log.id,
            alert_type=f'threat_intel_{indicator_type}',
            detection_method='threat_intel_matcher',
            severity=severity,
            description=description,
            metadata={
                'indicator_type': indicator_type,
                'indicator_value': indicator_value,
                'threat_type': threat_type,
                'confidence': confidence,
                'source': threat_intel.source,
                'threat_intel_id': threat_intel.id
            },
            source_ip=log.get_source_ip(),
            user=log.get_user(),
            host=log.host
        )
    
    def reload_threat_intel(self):
        """Reload threat intel from database"""
        self.threat_intel_cache.clear()
        self._load_threat_intel()
        logger.info("Threat intel reloaded", count=len(self.threat_intel_cache))
