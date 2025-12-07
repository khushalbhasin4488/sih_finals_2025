"""
Behavioral Analyzer (UEBA)
User and Entity Behavior Analytics - detects deviations from normal behavior
"""
import structlog
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict, Counter
import uuid

from storage.models import LogEntry, Alert, Severity

logger = structlog.get_logger()


class UserProfile:
    """Profile for a single user"""
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.typical_login_times = Counter()  # Hour of day distribution
        self.typical_login_days = Counter()   # Day of week distribution
        self.typical_source_ips = set()
        self.typical_accessed_resources = set()
        self.typical_actions = Counter()
        self.risk_score = 0.0
        self.last_updated = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary"""
        return {
            'user_id': self.user_id,
            'typical_login_times': dict(self.typical_login_times),
            'typical_login_days': dict(self.typical_login_days),
            'typical_source_ips': list(self.typical_source_ips),
            'typical_accessed_resources': list(self.typical_accessed_resources),
            'typical_actions': dict(self.typical_actions),
            'risk_score': self.risk_score,
            'last_updated': self.last_updated.isoformat()
        }


class BehavioralAnalyzer:
    """
    User and Entity Behavior Analytics
    Detects deviations from normal user/entity behavior patterns
    """
    
    def __init__(self, db_manager=None):
        """
        Initialize behavioral analyzer
        
        Args:
            db_manager: Optional database manager for historical profile building
        """
        self.db_manager = db_manager
        self.name = "behavioral_analyzer"
        self.user_profiles: Dict[str, UserProfile] = {}
        self.min_profile_data_points = 10  # Minimum data points to build profile
        
        logger.info("Behavioral analyzer initialized")
    
    async def analyze(self, logs: List[LogEntry]) -> List[Alert]:
        """
        Analyze logs for behavioral anomalies
        
        Args:
            logs: List of log entries to analyze
            
        Returns:
            List of alerts for behavioral deviations
        """
        if not logs:
            return []
        
        logger.info("Starting behavioral analysis", log_count=len(logs))
        alerts = []
        
        try:
            # Group logs by user
            user_logs = defaultdict(list)
            
            for log in logs:
                user = log.get_user()
                if user:
                    user_logs[user].append(log)
            
            # Analyze each user's behavior
            for user, user_logs_list in user_logs.items():
                # Get or create user profile
                profile = await self._get_user_profile(user)
                
                if not profile or len(profile.typical_login_times) < self.min_profile_data_points:
                    # Not enough data to build profile, skip
                    continue
                
                # Check for behavioral deviations
                user_alerts = self._analyze_user_behavior(user, user_logs_list, profile)
                alerts.extend(user_alerts)
            
            logger.info("Behavioral analysis completed", 
                       alerts_generated=len(alerts),
                       log_count=len(logs))
            
        except Exception as e:
            logger.error("Error in behavioral analysis", error=str(e))
        
        return alerts
    
    async def _get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile, building it if needed"""
        if user_id in self.user_profiles:
            return self.user_profiles[user_id]
        
        # Try to build profile from historical data
        if self.db_manager:
            try:
                # Fetch historical logs for this user (last 30 days)
                historical_logs = self.db_manager.fetch_logs(
                    limit=1000,
                    filters={'user': user_id} if hasattr(self.db_manager, 'fetch_logs') else None
                )
                
                if len(historical_logs) >= self.min_profile_data_points:
                    profile = self._build_profile(user_id, historical_logs)
                    self.user_profiles[user_id] = profile
                    return profile
            except Exception as e:
                logger.debug("Could not build profile from history", user=user_id, error=str(e))
        
        return None
    
    def _build_profile(self, user_id: str, logs: List[LogEntry]) -> UserProfile:
        """Build user profile from historical logs"""
        profile = UserProfile(user_id)
        
        for log in logs:
            log_time = log.get_timestamp()
            if not log_time:
                continue
            
            # Build login time distribution
            message_lower = (log.message or '').lower()
            if 'login' in message_lower or 'accepted' in message_lower:
                profile.typical_login_times[log_time.hour] += 1
                profile.typical_login_days[log_time.weekday()] += 1
            
            # Collect typical source IPs
            source_ip = log.get_source_ip()
            if source_ip:
                profile.typical_source_ips.add(source_ip)
            
            # Collect typical accessed resources
            if log.normalized and 'resource' in log.normalized:
                profile.typical_accessed_resources.add(log.normalized['resource'])
            
            # Track typical actions
            if log.normalized and 'action' in log.normalized:
                profile.typical_actions[log.normalized['action']] += 1
        
        profile.last_updated = datetime.now()
        return profile
    
    def _analyze_user_behavior(
        self, 
        user_id: str, 
        logs: List[LogEntry], 
        profile: UserProfile
    ) -> List[Alert]:
        """Analyze user behavior for deviations"""
        alerts = []
        
        for log in logs:
            log_time = log.get_timestamp()
            if not log_time:
                continue
            
            # Check for unusual login time
            if self._is_unusual_login_time(log, profile):
                alert = Alert(
                    id=str(uuid.uuid4()),
                    log_id=log.id,
                    alert_type='unusual_login_time',
                    detection_method='behavioral_analyzer',
                    severity=Severity.MEDIUM,
                    description=f"User {user_id} logged in at unusual time ({log_time.hour:02d}:00)",
                    metadata={
                        'user_id': user_id,
                        'login_hour': log_time.hour,
                        'typical_hours': list(profile.typical_login_times.keys()),
                        'deviation_type': 'time'
                    },
                    user=user_id,
                    host=log.host
                )
                alerts.append(alert)
            
            # Check for unusual source IP
            source_ip = log.get_source_ip()
            if source_ip and source_ip not in profile.typical_source_ips:
                alert = Alert(
                    id=str(uuid.uuid4()),
                    log_id=log.id,
                    alert_type='unusual_source_ip',
                    detection_method='behavioral_analyzer',
                    severity=Severity.HIGH,
                    description=f"User {user_id} accessed from unusual IP: {source_ip}",
                    metadata={
                        'user_id': user_id,
                        'source_ip': source_ip,
                        'typical_ips': list(profile.typical_source_ips),
                        'deviation_type': 'location'
                    },
                    user=user_id,
                    source_ip=source_ip,
                    host=log.host
                )
                alerts.append(alert)
            
            # Check for unusual resource access
            if log.normalized and 'resource' in log.normalized:
                resource = log.normalized['resource']
                if resource not in profile.typical_accessed_resources:
                    alert = Alert(
                        id=str(uuid.uuid4()),
                        log_id=log.id,
                        alert_type='unusual_resource_access',
                        detection_method='behavioral_analyzer',
                        severity=Severity.MEDIUM,
                        description=f"User {user_id} accessed unusual resource: {resource}",
                        metadata={
                            'user_id': user_id,
                            'resource': resource,
                            'typical_resources': list(profile.typical_accessed_resources),
                            'deviation_type': 'resource'
                        },
                        user=user_id,
                        host=log.host
                    )
                    alerts.append(alert)
            
            # Check for unusual action frequency
            if log.normalized and 'action' in log.normalized:
                action = log.normalized['action']
                typical_count = profile.typical_actions.get(action, 0)
                if typical_count > 0:
                    # Check if this action is being performed more frequently than usual
                    # This is a simplified check - in production, use time windows
                    pass
        
        return alerts
    
    def _is_unusual_login_time(self, log: LogEntry, profile: UserProfile) -> bool:
        """Check if login time is unusual"""
        log_time = log.get_timestamp()
        if not log_time:
            return False
        
        message_lower = (log.message or '').lower()
        if 'login' not in message_lower and 'accepted' not in message_lower:
            return False
        
        hour = log_time.hour
        
        # Check if this hour is in typical login hours
        if not profile.typical_login_times:
            return False
        
        # Get total logins
        total_logins = sum(profile.typical_login_times.values())
        if total_logins == 0:
            return False
        
        # Calculate probability of login at this hour
        hour_count = profile.typical_login_times.get(hour, 0)
        probability = hour_count / total_logins
        
        # If probability is less than 5%, it's unusual
        return probability < 0.05
    
    def update_profile(self, user_id: str, logs: List[LogEntry]):
        """Update user profile with new logs"""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserProfile(user_id)
        
        profile = self.user_profiles[user_id]
        
        for log in logs:
            log_time = log.get_timestamp()
            if not log_time:
                continue
            
            message_lower = (log.message or '').lower()
            if 'login' in message_lower or 'accepted' in message_lower:
                profile.typical_login_times[log_time.hour] += 1
                profile.typical_login_days[log_time.weekday()] += 1
            
            source_ip = log.get_source_ip()
            if source_ip:
                profile.typical_source_ips.add(source_ip)
            
            if log.normalized and 'resource' in log.normalized:
                profile.typical_accessed_resources.add(log.normalized['resource'])
            
            if log.normalized and 'action' in log.normalized:
                profile.typical_actions[log.normalized['action']] += 1
        
        profile.last_updated = datetime.now()
