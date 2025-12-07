"""
Baseline Manager for Anomaly Detection
Maintains historical baselines and statistics for detecting anomalies
"""
import structlog
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import json

logger = structlog.get_logger()


class BaselineManager:
    """
    Manages baseline statistics for anomaly detection
    Calculates and stores historical baselines for various metrics
    """
    
    def __init__(self, db_manager, baseline_file: str = "data/baselines.json"):
        """
        Initialize baseline manager
        
        Args:
            db_manager: Database manager instance
            baseline_file: Path to store baseline data
        """
        self.db_manager = db_manager
        self.baseline_file = Path(baseline_file)
        self.baselines: Dict[str, Dict[str, Any]] = {}
        
        # Ensure baseline directory exists
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing baselines
        self.load_baselines()
        
        logger.info("Baseline manager initialized", baseline_file=str(self.baseline_file))
    
    def load_baselines(self):
        """Load baselines from file"""
        try:
            if self.baseline_file.exists():
                with open(self.baseline_file, 'r') as f:
                    data = json.load(f)
                    self.baselines = data
                logger.info("Loaded baselines", count=len(self.baselines))
            else:
                logger.info("No existing baselines found, will create new")
        except Exception as e:
            logger.error("Error loading baselines", error=str(e))
            self.baselines = {}
    
    def save_baselines(self):
        """Save baselines to file"""
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baselines, f, indent=2, default=str)
            logger.info("Saved baselines", count=len(self.baselines))
        except Exception as e:
            logger.error("Error saving baselines", error=str(e))
    
    def calculate_baseline(self, metric_name: str, values: List[float]) -> Dict[str, Any]:
        """
        Calculate baseline statistics for a metric
        
        Args:
            metric_name: Name of the metric
            values: Historical values
            
        Returns:
            Dictionary of baseline statistics
        """
        if not values or len(values) < 10:
            logger.warning("Insufficient data for baseline", metric=metric_name, count=len(values))
            return {}
        
        values_array = np.array(values)
        
        baseline = {
            'mean': float(np.mean(values_array)),
            'std': float(np.std(values_array)),
            'median': float(np.median(values_array)),
            'q1': float(np.percentile(values_array, 25)),
            'q3': float(np.percentile(values_array, 75)),
            'iqr': float(np.percentile(values_array, 75) - np.percentile(values_array, 25)),
            'min': float(np.min(values_array)),
            'max': float(np.max(values_array)),
            'count': len(values),
            'updated_at': datetime.now().isoformat()
        }
        
        logger.info("Calculated baseline", metric=metric_name, **{k: v for k, v in baseline.items() if k != 'updated_at'})
        
        return baseline
    
    def update_baseline(self, metric_name: str, values: List[float]):
        """
        Update baseline for a specific metric
        
        Args:
            metric_name: Name of the metric
            values: Historical values
        """
        baseline = self.calculate_baseline(metric_name, values)
        if baseline:
            self.baselines[metric_name] = baseline
            self.save_baselines()
    
    def get_baseline(self, metric_name: str) -> Optional[Dict[str, Any]]:
        """
        Get baseline for a metric
        
        Args:
            metric_name: Name of the metric
            
        Returns:
            Baseline statistics or None
        """
        return self.baselines.get(metric_name)
    
    def update_all_baselines(self, historical_days: int = 7):
        """
        Update all baselines using historical data
        
        Args:
            historical_days: Number of days of historical data to use
        """
        logger.info("Updating all baselines", days=historical_days)
        
        try:
            # Get historical logs
            start_time = datetime.now() - timedelta(days=historical_days)
            logs = self.db_manager.fetch_logs(
                start_time=start_time,
                limit=100000
            )
            
            if not logs:
                logger.warning("No historical logs found for baseline calculation")
                return
            
            logger.info("Fetched historical logs for baseline", count=len(logs))
            
            # Calculate baselines for different metrics
            self._calculate_login_baselines(logs)
            self._calculate_request_baselines(logs)
            self._calculate_error_baselines(logs)
            self._calculate_host_baselines(logs)
            
            self.save_baselines()
            logger.info("All baselines updated successfully")
            
        except Exception as e:
            logger.error("Error updating baselines", error=str(e))
    
    def _calculate_login_baselines(self, logs: List):
        """Calculate baselines for login-related metrics"""
        # Group logs by hour and count logins
        from collections import defaultdict
        hourly_logins = defaultdict(int)
        hourly_failed_logins = defaultdict(int)
        
        for log in logs:
            if not log.message:
                continue
            
            message_lower = log.message.lower()
            hour_key = log.timestamp[:13]  # YYYY-MM-DDTHH
            
            if 'login' in message_lower or 'accepted' in message_lower:
                hourly_logins[hour_key] += 1
            
            if 'failed' in message_lower and 'login' in message_lower:
                hourly_failed_logins[hour_key] += 1
        
        # Update baselines
        if hourly_logins:
            self.update_baseline('login_frequency', list(hourly_logins.values()))
        if hourly_failed_logins:
            self.update_baseline('failed_login_rate', list(hourly_failed_logins.values()))
    
    def _calculate_request_baselines(self, logs: List):
        """Calculate baselines for request-related metrics"""
        from collections import defaultdict
        
        # Group by source IP and count requests
        ip_requests = defaultdict(int)
        
        for log in logs:
            source_ip = log.get_source_ip()
            if source_ip:
                ip_requests[source_ip] += 1
        
        if ip_requests:
            self.update_baseline('requests_per_ip', list(ip_requests.values()))
    
    def _calculate_error_baselines(self, logs: List):
        """Calculate baselines for error-related metrics"""
        from collections import defaultdict
        
        # Group by hour and count errors
        hourly_errors = defaultdict(int)
        
        for log in logs:
            if not log.message:
                continue
            
            message_lower = log.message.lower()
            hour_key = log.timestamp[:13]
            
            if any(keyword in message_lower for keyword in ['error', 'fail', 'exception', 'denied']):
                hourly_errors[hour_key] += 1
        
        if hourly_errors:
            self.update_baseline('error_rate', list(hourly_errors.values()))
    
    def _calculate_host_baselines(self, logs: List):
        """Calculate baselines for host-related metrics"""
        from collections import defaultdict
        
        # Count unique hosts per hour
        hourly_hosts = defaultdict(set)
        
        for log in logs:
            if log.host:
                hour_key = log.timestamp[:13]
                hourly_hosts[hour_key].add(log.host)
        
        # Convert to counts
        host_counts = [len(hosts) for hosts in hourly_hosts.values()]
        
        if host_counts:
            self.update_baseline('unique_hosts', host_counts)
