"""
Network Traffic Analyzer
Analyzes network flow logs for suspicious patterns
"""
import structlog
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


class NetworkAnalyzer:
    """
    Analyzes network traffic patterns for anomalies
    Detects port scanning, DDoS, beaconing, protocol anomalies, etc.
    """
    
    def __init__(self, db_manager=None):
        """
        Initialize network analyzer
        
        Args:
            db_manager: Optional database manager for historical queries
        """
        self.db_manager = db_manager
        self.name = "network_analyzer"
        
        # Configuration
        self.port_scan_threshold = 20  # Unique ports in time window
        self.beaconing_variance_threshold = 0.2  # Coefficient of variation
        self.ddos_threshold = 1000  # Connections per minute
        self.dns_tunneling_threshold = 100  # DNS queries per minute
        
        logger.info("Network analyzer initialized")
    
    async def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze network logs for suspicious patterns
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for detected network anomalies
        """
        if not logs:
            return []
        
        logger.info("Starting network analysis", log_count=len(logs))
        alerts = []
        
        try:
            # Filter network-related logs
            network_logs = self._filter_network_logs(logs)
            
            if not network_logs:
                return []
            
            # Run different network analysis techniques
            alerts.extend(await self._detect_port_scanning(network_logs))
            alerts.extend(await self._detect_ddos(network_logs))
            alerts.extend(await self._detect_beaconing(network_logs))
            alerts.extend(await self._detect_dns_tunneling(network_logs))
            alerts.extend(await self._detect_protocol_anomalies(network_logs))
            alerts.extend(await self._detect_bandwidth_anomalies(network_logs))
            
            logger.info("Network analysis completed", 
                       alerts_generated=len(alerts),
                       network_logs=len(network_logs))
            
        except Exception as e:
            logger.error("Error in network analysis", error=str(e))
        
        return alerts
    
    def _filter_network_logs(self, logs: List[LogEntry]) -> List[LogEntry]:
        """Filter logs that are network-related"""
        network_logs = []
        
        for log in logs:
            message_lower = (log.message or '').lower()
            
            # Check if it's a network-related log
            is_network = (
                'connection' in message_lower or
                'connect' in message_lower or
                'network' in message_lower or
                'tcp' in message_lower or
                'udp' in message_lower or
                'http' in message_lower or
                'https' in message_lower or
                'dns' in message_lower or
                'port' in message_lower or
                (log.normalized and (
                    'protocol' in log.normalized or
                    'source_port' in log.normalized or
                    'dest_port' in log.normalized
                ))
            )
            
            if is_network:
                network_logs.append(log)
        
        return network_logs
    
    async def _detect_port_scanning(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect port scanning activity"""
        alerts = []
        
        # Group by source IP
        by_source = defaultdict(lambda: {'ports': set(), 'logs': []})
        
        for log in logs:
            source_ip = log.get_source_ip()
            if not source_ip:
                continue
            
            # Extract destination port
            dest_port = None
            if log.normalized and 'dest_port' in log.normalized:
                dest_port = log.normalized['dest_port']
            elif log.normalized and 'port' in log.normalized:
                dest_port = log.normalized['port']
            else:
                # Try to extract from message
                import re
                port_match = re.search(r'port[:\s]+(\d+)', (log.message or ''), re.IGNORECASE)
                if port_match:
                    dest_port = int(port_match.group(1))
            
            if dest_port:
                by_source[source_ip]['ports'].add(dest_port)
                by_source[source_ip]['logs'].append(log)
        
        # Check for scanning patterns
        window = timedelta(minutes=1)
        
        for source_ip, data in by_source.items():
            if len(data['ports']) >= self.port_scan_threshold:
                # Check if ports were scanned within time window
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
                            alert_type='port_scan',
                            detection_method='network_analyzer',
                            severity=Severity.HIGH,
                            description=f"Port scanning detected: {len(data['ports'])} unique ports scanned from {source_ip}",
                            metadata={
                                'source_ip': source_ip,
                                'unique_ports': len(data['ports']),
                                'ports': sorted(list(data['ports']))[:20],  # First 20 ports
                                'time_window_minutes': 1,
                                'threshold': self.port_scan_threshold
                            },
                            source_ip=source_ip
                        )
                        alerts.append(alert)
        
        return alerts
    
    async def _detect_ddos(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect DDoS attack patterns"""
        alerts = []
        
        # Group by destination IP
        by_dest = defaultdict(lambda: {'count': 0, 'sources': set(), 'logs': []})
        
        for log in logs:
            dest_ip = None
            if log.normalized and 'dest_ip' in log.normalized:
                dest_ip = log.normalized['dest_ip']
            
            if not dest_ip:
                continue
            
            source_ip = log.get_source_ip()
            by_dest[dest_ip]['count'] += 1
            if source_ip:
                by_dest[dest_ip]['sources'].add(source_ip)
            by_dest[dest_ip]['logs'].append(log)
        
        # Check for DDoS patterns (many connections to single destination)
        window = timedelta(minutes=1)
        
        for dest_ip, data in by_dest.items():
            if data['count'] >= self.ddos_threshold:
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
                            alert_type='ddos_attack',
                            detection_method='network_analyzer',
                            severity=Severity.CRITICAL,
                            description=f"DDoS attack detected: {data['count']} connections to {dest_ip} from {len(data['sources'])} sources",
                            metadata={
                                'dest_ip': dest_ip,
                                'connection_count': data['count'],
                                'unique_sources': len(data['sources']),
                                'sources': list(data['sources'])[:20],  # First 20 sources
                                'time_window_minutes': 1,
                                'threshold': self.ddos_threshold
                            },
                            dest_ip=dest_ip
                        )
                        alerts.append(alert)
        
        return alerts
    
    async def _detect_beaconing(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect C2 beaconing (regular periodic connections)"""
        alerts = []
        
        # Group by source IP and destination IP
        connections = defaultdict(list)
        
        for log in logs:
            source_ip = log.get_source_ip()
            dest_ip = None
            if log.normalized and 'dest_ip' in log.normalized:
                dest_ip = log.normalized['dest_ip']
            
            if source_ip and dest_ip:
                key = (source_ip, dest_ip)
                log_time = log.get_timestamp()
                if log_time:
                    connections[key].append(log_time)
        
        # Analyze connection intervals
        for (source_ip, dest_ip), timestamps in connections.items():
            if len(timestamps) < 5:
                continue
            
            # Calculate intervals
            sorted_times = sorted(timestamps)
            intervals = [
                (sorted_times[i+1] - sorted_times[i]).total_seconds()
                for i in range(len(sorted_times) - 1)
            ]
            
            if len(intervals) > 0:
                mean_interval = np.mean(intervals)
                std_interval = np.std(intervals) if len(intervals) > 1 else 0
                
                # Coefficient of variation < threshold indicates regular beaconing
                if mean_interval > 0:
                    cv = std_interval / mean_interval
                    
                    if cv < self.beaconing_variance_threshold:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            log_id=None,  # No specific log ID
                            alert_type='beaconing',
                            detection_method='network_analyzer',
                            severity=Severity.CRITICAL,
                            description=f"C2 beaconing detected: regular connections from {source_ip} to {dest_ip}",
                            metadata={
                                'source_ip': source_ip,
                                'dest_ip': dest_ip,
                                'connection_count': len(timestamps),
                                'mean_interval_seconds': mean_interval,
                                'coefficient_of_variation': cv,
                                'threshold': self.beaconing_variance_threshold
                            },
                            source_ip=source_ip,
                            dest_ip=dest_ip
                        )
                        alerts.append(alert)
        
        return alerts
    
    async def _detect_dns_tunneling(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect DNS tunneling (excessive DNS queries)"""
        alerts = []
        
        # Group DNS queries by source IP
        by_source = defaultdict(lambda: {'count': 0, 'logs': []})
        
        for log in logs:
            message_lower = (log.message or '').lower()
            if 'dns' in message_lower or (log.normalized and log.normalized.get('protocol') == 'dns'):
                source_ip = log.get_source_ip()
                if source_ip:
                    by_source[source_ip]['count'] += 1
                    by_source[source_ip]['logs'].append(log)
        
        # Check for excessive DNS queries
        window = timedelta(minutes=1)
        
        for source_ip, data in by_source.items():
            if data['count'] >= self.dns_tunneling_threshold:
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
                            alert_type='dns_tunneling',
                            detection_method='network_analyzer',
                            severity=Severity.HIGH,
                            description=f"DNS tunneling suspected: {data['count']} DNS queries from {source_ip}",
                            metadata={
                                'source_ip': source_ip,
                                'dns_query_count': data['count'],
                                'time_window_minutes': 1,
                                'threshold': self.dns_tunneling_threshold
                            },
                            source_ip=source_ip
                        )
                        alerts.append(alert)
        
        return alerts
    
    async def _detect_protocol_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect protocol anomalies"""
        alerts = []
        
        # Check for unusual protocol usage
        protocol_counts = defaultdict(int)
        
        for log in logs:
            protocol = None
            if log.normalized and 'protocol' in log.normalized:
                protocol = log.normalized['protocol']
            
            if protocol:
                protocol_counts[protocol] += 1
        
        # Check for protocols on unusual ports
        for log in logs:
            protocol = None
            dest_port = None
            
            if log.normalized:
                protocol = log.normalized.get('protocol')
                dest_port = log.normalized.get('dest_port')
            
            if protocol and dest_port:
                # Check for unusual port/protocol combinations
                unusual_combos = {
                    ('http', 8080): False,  # HTTP on non-standard port
                    ('https', 8443): False,  # HTTPS on non-standard port
                    ('ssh', 2222): False,    # SSH on non-standard port
                }
                
                if (protocol.lower(), dest_port) not in [(p.lower(), port) for p, port in unusual_combos.keys()]:
                    # Check if it's a known unusual combination
                    if protocol.lower() in ['http', 'https'] and dest_port not in [80, 443, 8080, 8443]:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            log_id=log.id,
                            alert_type='protocol_anomaly',
                            detection_method='network_analyzer',
                            severity=Severity.MEDIUM,
                            description=f"Unusual protocol/port combination: {protocol} on port {dest_port}",
                            metadata={
                                'protocol': protocol,
                                'dest_port': dest_port,
                                'source_ip': log.get_source_ip(),
                                'dest_ip': log.normalized.get('dest_ip') if log.normalized else None
                            },
                            source_ip=log.get_source_ip()
                        )
                        alerts.append(alert)
        
        return alerts
    
    async def _detect_bandwidth_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect bandwidth anomalies"""
        alerts = []
        
        # Group by source IP and calculate bandwidth
        by_source = defaultdict(lambda: {'bytes': 0, 'logs': []})
        
        for log in logs:
            source_ip = log.get_source_ip()
            if not source_ip:
                continue
            
            # Extract bytes transferred
            bytes_transferred = 0
            if log.normalized and 'bytes' in log.normalized:
                bytes_transferred = int(log.normalized.get('bytes', 0))
            
            if bytes_transferred > 0:
                by_source[source_ip]['bytes'] += bytes_transferred
                by_source[source_ip]['logs'].append(log)
        
        # Check for high bandwidth usage (potential data exfiltration)
        window = timedelta(minutes=5)
        threshold_bytes = 100 * 1024 * 1024  # 100MB
        
        for source_ip, data in by_source.items():
            if data['bytes'] >= threshold_bytes:
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
                            alert_type='bandwidth_anomaly',
                            detection_method='network_analyzer',
                            severity=Severity.HIGH,
                            description=f"High bandwidth usage detected: {data['bytes']:,} bytes from {source_ip}",
                            metadata={
                                'source_ip': source_ip,
                                'bytes_transferred': data['bytes'],
                                'time_window_minutes': 5,
                                'threshold_bytes': threshold_bytes
                            },
                            source_ip=source_ip
                        )
                        alerts.append(alert)
        
        return alerts
