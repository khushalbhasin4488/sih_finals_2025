"""
Analysis Orchestrator
Coordinates all detection engines and manages the analysis pipeline
"""
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import structlog
import uuid

from storage.db_manager import DuckDBManager
from storage.models import LogEntry, Alert

logger = structlog.get_logger()


class AnalysisOrchestrator:
    """
    Orchestrates the analysis pipeline
    Fetches logs, runs detectors, aggregates and stores alerts
    """
    
    def __init__(
        self,
        db_manager: DuckDBManager,
        config: Dict[str, Any]
    ):
        """
        Initialize orchestrator
        
        Args:
            db_manager: Database manager instance
            config: Configuration dictionary
        """
        self.db_manager = db_manager
        self.config = config
        
        # Analysis state
        self.last_processed_timestamp: Optional[datetime] = None
        self.is_running = False
        
        # Performance metrics
        self.metrics = {
            'total_cycles': 0,
            'total_logs_processed': 0,
            'total_alerts_generated': 0,
            'average_cycle_time': 0.0
        }
        
        # Initialize detectors
        self.detectors = []
        self._initialize_detectors()
        
        logger.info(
            "Analysis orchestrator initialized",
            detectors=len(self.detectors),
            interval=self.config.get('analysis_interval', 60)
        )
    
    def _initialize_detectors(self):
        """Initialize the 4 focused detection engines"""
        
        # 1. Brute Force Detector (Authentication Attacks)
        try:
            from analyzers.brute_force_detector import BruteForceDetector
            brute_force_detector = BruteForceDetector(
                rules_file=self.config.get('signature_dir', 'config/signatures') + '/auth_attacks.yaml'
            )
            self.detectors.append(brute_force_detector)
            logger.info("Brute force detector initialized")
        except Exception as e:
            logger.error("Failed to initialize brute force detector", error=str(e))
        
        # 2. Web Attack Detector
        try:
            from analyzers.web_attack_detector import WebAttackDetector
            web_attack_detector = WebAttackDetector(
                rules_file=self.config.get('signature_dir', 'config/signatures') + '/web_attacks.yaml'
            )
            self.detectors.append(web_attack_detector)
            logger.info("Web attack detector initialized")
        except Exception as e:
            logger.error("Failed to initialize web attack detector", error=str(e))
        
        # 3. Network Pattern Detector
        try:
            from analyzers.network_pattern_detector import NetworkPatternDetector
            network_pattern_detector = NetworkPatternDetector()
            self.detectors.append(network_pattern_detector)
            logger.info("Network pattern detector initialized")
        except Exception as e:
            logger.error("Failed to initialize network pattern detector", error=str(e))
        
        # 4. Privilege Abuse Detector
        try:
            from analyzers.privilege_abuse_detector import PrivilegeAbuseDetector
            privilege_abuse_detector = PrivilegeAbuseDetector(
                rules_file=self.config.get('signature_dir', 'config/signatures') + '/privilege_abuse.yaml'
            )
            self.detectors.append(privilege_abuse_detector)
            logger.info("Privilege abuse detector initialized")
        except Exception as e:
            logger.error("Failed to initialize privilege abuse detector", error=str(e))
        
        logger.info("All detectors initialized", total_detectors=len(self.detectors))
    
    async def run_analysis_cycle(self) -> Dict[str, Any]:
        """
        Run one analysis cycle
        
        Returns:
            Dictionary with cycle statistics
        """
        cycle_start = datetime.now()
        
        try:
            # 1. Fetch new logs
            new_logs = await self._fetch_new_logs()
            
            if not new_logs:
                logger.debug("No new logs to process")
                return {
                    'logs_processed': 0,
                    'alerts_generated': 0,
                    'cycle_time': 0.0
                }
            
            logger.info("Fetched new logs", count=len(new_logs))
            
            # 2. Run all detectors in parallel
            detection_tasks = [
                detector.analyze(new_logs)
                for detector in self.detectors
            ]
            
            results = await asyncio.gather(*detection_tasks, return_exceptions=True)
            
            # 3. Aggregate alerts from all detectors
            all_alerts = self._aggregate_results(results)
            
            logger.info("Detection completed", alerts=len(all_alerts))
            
            # 4. Prioritize alerts
            prioritized_alerts = self._prioritize_alerts(all_alerts)
            
            # 5. Deduplicate alerts
            unique_alerts = self._deduplicate_alerts(prioritized_alerts)
            
            logger.info("Alerts processed", unique_alerts=len(unique_alerts))
            
            # 6. Store alerts
            if unique_alerts:
                stored_count = await self._store_alerts(unique_alerts)
                logger.info("Alerts stored", count=stored_count)
            
            # 7. Update metrics
            cycle_time = (datetime.now() - cycle_start).total_seconds()
            self._update_metrics(len(new_logs), len(unique_alerts), cycle_time)
            
            # 8. Update last processed timestamp
            if new_logs:
                self.last_processed_timestamp = max(
                    log.get_timestamp() or datetime.now()
                    for log in new_logs
                )
            
            return {
                'logs_processed': len(new_logs),
                'alerts_generated': len(unique_alerts),
                'cycle_time': cycle_time
            }
            
        except Exception as e:
            logger.error("Error in analysis cycle", error=str(e))
            raise
    
    async def _fetch_new_logs(self) -> List[LogEntry]:
        """
        Fetch new logs since last cycle
        
        Returns:
            List of new log entries
        """
        end_time = datetime.now()
        
        if self.last_processed_timestamp is None:
            # First run - fetch logs from last interval
            interval = self.config.get('analysis_interval', 60)
            start_time = end_time - timedelta(seconds=interval)
        else:
            # Subsequent runs - fetch since last processed
            start_time = self.last_processed_timestamp
        
        logs = self.db_manager.fetch_logs(
            start_time=start_time,
            end_time=end_time,
            limit=self.config.get('batch_size', 10000)
        )
        
        return logs
    
    def _aggregate_results(self, results: List[Any]) -> List[Alert]:
        """
        Aggregate alerts from all detectors
        
        Args:
            results: List of results from detectors (may include exceptions)
        
        Returns:
            Combined list of alerts
        """
        all_alerts = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "Detector failed",
                    detector_index=i,
                    error=str(result)
                )
                continue
            
            if isinstance(result, list):
                all_alerts.extend(result)
        
        return all_alerts
    
    def _prioritize_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """
        Calculate priority scores for alerts
        
        Args:
            alerts: List of alerts
        
        Returns:
            Alerts with priority scores
        """
        severity_weights = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25,
            'info': 10
        }
        
        for alert in alerts:
            # Base score from severity
            base_score = severity_weights.get(alert.severity, 50)
            
            # Adjust based on detection method confidence
            # (can be enhanced with more sophisticated scoring)
            alert.priority_score = float(base_score)
        
        # Sort by priority (highest first)
        alerts.sort(key=lambda x: x.priority_score, reverse=True)
        
        return alerts
    
    def _deduplicate_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """
        Remove duplicate or similar alerts
        
        Args:
            alerts: List of alerts
        
        Returns:
            Deduplicated alerts
        """
        # Simple deduplication based on alert type, host, and source IP
        seen = set()
        unique_alerts = []
        
        for alert in alerts:
            # Create a key for deduplication
            key = (
                alert.alert_type,
                alert.host,
                alert.source_ip,
                alert.user
            )
            
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)
        
        return unique_alerts
    
    async def _store_alerts(self, alerts: List[Alert]) -> int:
        """
        Store alerts in database
        
        Args:
            alerts: List of alerts to store
        
        Returns:
            Number of alerts stored
        """
        try:
            return self.db_manager.store_alerts_batch(alerts)
        except Exception as e:
            logger.error("Failed to store alerts", error=str(e))
            raise
    
    def _update_metrics(self, logs_count: int, alerts_count: int, cycle_time: float):
        """Update performance metrics"""
        self.metrics['total_cycles'] += 1
        self.metrics['total_logs_processed'] += logs_count
        self.metrics['total_alerts_generated'] += alerts_count
        
        # Update average cycle time
        total_cycles = self.metrics['total_cycles']
        prev_avg = self.metrics['average_cycle_time']
        self.metrics['average_cycle_time'] = (
            (prev_avg * (total_cycles - 1) + cycle_time) / total_cycles
        )
    
    async def start(self, interval: Optional[int] = None):
        """
        Start continuous analysis
        
        Args:
            interval: Analysis interval in seconds (overrides config)
        """
        self.is_running = True
        analysis_interval = interval or self.config.get('analysis_interval', 60)
        
        logger.info("Starting analysis orchestrator", interval=analysis_interval)
        
        while self.is_running:
            try:
                stats = await self.run_analysis_cycle()
                
                logger.info(
                    "Analysis cycle completed",
                    **stats,
                    total_cycles=self.metrics['total_cycles']
                )
                
                # Wait for next cycle
                await asyncio.sleep(analysis_interval)
                
            except Exception as e:
                logger.error("Error in analysis loop", error=str(e))
                # Continue running even if there's an error
                await asyncio.sleep(analysis_interval)
    
    def stop(self):
        """Stop continuous analysis"""
        self.is_running = False
        logger.info("Stopping analysis orchestrator")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return self.metrics.copy()
    
    def reload_detectors(self):
        """Reload all detectors (useful for updating signatures/rules)"""
        logger.info("Reloading detectors")
        
        for detector in self.detectors:
            if hasattr(detector, 'reload_signatures'):
                detector.reload_signatures()
            if hasattr(detector, 'reload_blocked_ips'):
                detector.reload_blocked_ips()
        
        logger.info("Detectors reloaded")
