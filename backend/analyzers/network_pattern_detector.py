"""
Network Pattern Detector
Detects network anomalies and scanning activity through connection pattern analysis

Focus: Port scanning, connection spikes, beaconing, unusual network behavior
"""
import re
from pathlib import Path
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import structlog
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


class NetworkPatternDetector:
    """
    Detects network anomalies using:
    - Port scan detection (many ports from single IP)
    - Connection spike analysis
    - Beaconing detection (regular interval connections)
    """
    
    def __init__(self):
        """Initialize network pattern detector"""
        self.port_scan_threshold = 10  # Unique ports to consider as scan
        self.port_scan_window = 60  # 60 second window
        self.connection_spike_threshold = 50  # Connections per minute
        
        logger.info("NetworkPatternDetector initialized")
    
    def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs for network patterns
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for detected network anomalies
        """
        alerts = []
        
        # Filter for network/firewall logs
        network_logs = [
            log for log in logs 
            if log.source_type in ['firewall', 'network'] or 
               log.appname in ['iptables', 'firewalld', 'pf']
        ]
        
        logger.info(
            "Analyzing network logs",
            total_logs=len(logs),
            network_logs=len(network_logs)
        )
        
        if not network_logs:
            return alerts
        
        # Port scan detection
        port_scan_alerts = self._detect_port_scans(network_logs)
        alerts.extend(port_scan_alerts)
        
        # Connection spike detection
        spike_alerts = self._detect_connection_spikes(network_logs)
        alerts.extend(spike_alerts)
        
        # Beaconing detection
        beacon_alerts = self._detect_beaconing(network_logs)
        alerts.extend(beacon_alerts)
        
        logger.info(
            "Network pattern analysis complete",
            logs_analyzed=len(network_logs),
            alerts_generated=len(alerts)
        )
        
        return alerts
    
    def _detect_port_scans(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Detect port scanning activity
        
        A port scan is identified when a single IP attempts to connect to
        many different ports in a short time window
        
        Args:
            logs: Network logs to analyze
            
        Returns:
            List of port scan alerts
        """
        alerts = []
        
        # Group by source IP and extract port information
        ip_port_activity = defaultdict(lambda: {'ports': set(), 'logs': []})
        
        for log in logs:
            source_ip = log.get_source_ip()
            if not source_ip:
                # Try to extract from message
                source_ip = self._extract_ip_from_message(log.message, 'SRC')
            
            if not source_ip:
                continue
            
            # Extract destination port
            dest_port = self._extract_port_from_message(log.message)
            
            if dest_port:
                ip_port_activity[source_ip]['ports'].add(dest_port)
                ip_port_activity[source_ip]['logs'].append(log)
        
        # Check for port scans
        for source_ip, activity in ip_port_activity.items():
            unique_ports = len(activity['ports'])
            
            if unique_ports >= self.port_scan_threshold:
                # Verify it's within time window
                logs_list = activity['logs']
                timestamps = [log.get_timestamp() for log in logs_list if log.get_timestamp()]
                
                if len(timestamps) >= 2:
                    time_span = (max(timestamps) - min(timestamps)).total_seconds()
                    
                    if time_span <= self.port_scan_window:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            log_id=logs_list[0].id,
                            alert_type="port_scan",
                            detection_method="network_pattern_detector",
                            severity=Severity.MEDIUM,
                            description=f"Port scan detected: {source_ip} scanned {unique_ports} unique ports in {int(time_span)}s",
                            metadata={
                                "source_ip": source_ip,
                                "unique_ports_scanned": unique_ports,
                                "ports": sorted(list(activity['ports']))[:20],  # Sample
                                "time_span_seconds": time_span,
                                "scan_rate": round(unique_ports / (time_span / 60), 2)  # ports per minute
                            },
                            created_at=datetime.now(),
                            source_ip=source_ip,
                            host=logs_list[0].host
                        )
                        alerts.append(alert)
        
        return alerts
    
    def _detect_connection_spikes(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Detect unusual spikes in connection attempts
        
        Args:
            logs: Network logs to analyze
            
        Returns:
            List of connection spike alerts
        """
        alerts = []
        
        # Group connections by IP and time bucket (1 minute)
        ip_time_buckets = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            source_ip = log.get_source_ip()
            if not source_ip:
                source_ip = self._extract_ip_from_message(log.message, 'SRC')
            
            if not source_ip:
                continue
            
            timestamp = log.get_timestamp()
            if not timestamp:
                continue
            
            # Round to minute bucket
            time_bucket = timestamp.replace(second=0, microsecond=0)
            ip_time_buckets[source_ip][time_bucket] += 1
        
        # Check for spikes
        for source_ip, time_buckets in ip_time_buckets.items():
            for time_bucket, connection_count in time_buckets.items():
                if connection_count >= self.connection_spike_threshold:
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        log_id=None,  # Aggregate alert
                        alert_type="connection_spike",
                        detection_method="network_pattern_detector",
                        severity=Severity.MEDIUM,
                        description=f"Connection spike detected: {connection_count} connections from {source_ip} in 1 minute",
                        metadata={
                            "source_ip": source_ip,
                            "connection_count": connection_count,
                            "time_bucket": time_bucket.isoformat(),
                            "threshold": self.connection_spike_threshold
                        },
                        created_at=datetime.now(),
                        source_ip=source_ip
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_beaconing(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Detect beaconing behavior (regular interval connections)
        
        Beaconing is characteristic of malware C2 communication
        
        Args:
            logs: Network logs to analyze
            
        Returns:
            List of beaconing alerts
        """
        alerts = []
        
        # Group by source IP
        ip_connections = defaultdict(list)
        
        for log in logs:
            source_ip = log.get_source_ip()
            if not source_ip:
                source_ip = self._extract_ip_from_message(log.message, 'SRC')
            
            if source_ip:
                timestamp = log.get_timestamp()
                if timestamp:
                    ip_connections[source_ip].append((timestamp, log))
        
        # Analyze interval regularity
        for source_ip, connections in ip_connections.items():
            if len(connections) < 5:  # Need at least 5 connections
                continue
            
            # Sort by timestamp
            sorted_connections = sorted(connections, key=lambda x: x[0])
            timestamps = [ts for ts, _ in sorted_connections]
            
            # Calculate intervals
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if len(intervals) < 4:
                continue
            
            # Check for regular intervals (low variance)
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # Coefficient of variation (should be low for beaconing)
            if avg_interval > 0:
                coefficient_of_variation = std_dev / avg_interval
                
                # Regular beaconing has low coefficient of variation (< 0.3)
                if coefficient_of_variation < 0.3 and avg_interval > 30:  # At least 30s intervals
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        log_id=sorted_connections[0][1].id,
                        alert_type="beaconing",
                        detection_method="network_pattern_detector",
                        severity=Severity.HIGH,
                        description=f"Beaconing behavior detected: Regular connections from {source_ip} every {int(avg_interval)}s",
                        metadata={
                            "source_ip": source_ip,
                            "connection_count": len(connections),
                            "average_interval_seconds": round(avg_interval, 2),
                            "coefficient_of_variation": round(coefficient_of_variation, 3),
                            "std_deviation": round(std_dev, 2)
                        },
                        created_at=datetime.now(),
                        source_ip=source_ip,
                        host=sorted_connections[0][1].host
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _extract_ip_from_message(self, message: str, prefix: str = 'SRC') -> str:
        """
        Extract IP address from firewall log message
        
        Args:
            message: Log message
            prefix: 'SRC' or 'DST'
            
        Returns:
            IP address or None
        """
        if not message:
            return None
        
        # Common patterns: SRC=1.2.3.4 or src=1.2.3.4
        pattern = rf'{prefix}=(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})'
        match = re.search(pattern, message, re.IGNORECASE)
        
        if match:
            return match.group(1)
        
        return None
    
    def _extract_port_from_message(self, message: str) -> int:
        """
        Extract destination port from firewall log message
        
        Args:
            message: Log message
            
        Returns:
            Port number or None
        """
        if not message:
            return None
        
        # Common patterns: DPT=80 or dst_port=443
        patterns = [
            r'DPT=(\d+)',
            r'dst_port=(\d+)',
            r'port\s+(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        return None
