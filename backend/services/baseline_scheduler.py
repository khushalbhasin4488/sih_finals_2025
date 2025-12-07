"""
Baseline Scheduler
Manages automatic baseline updates on a schedule
"""
import threading
import time
import structlog
from datetime import datetime, timedelta
from typing import Optional

logger = structlog.get_logger()


class BaselineScheduler:
    """
    Schedules periodic baseline updates
    """
    
    def __init__(self, baseline_manager, update_interval: int = 86400, historical_days: int = 7):
        """
        Initialize baseline scheduler
        
        Args:
            baseline_manager: BaselineManager instance
            update_interval: Update interval in seconds (default: 86400 = 24 hours)
            historical_days: Days of historical data to use (default: 7)
        """
        self.baseline_manager = baseline_manager
        self.update_interval = update_interval
        self.historical_days = historical_days
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.last_update: Optional[datetime] = None
        
        logger.info(
            "Baseline scheduler initialized",
            update_interval=update_interval,
            historical_days=historical_days
        )
    
    def start(self):
        """Start the baseline scheduler in a background thread"""
        if self.running:
            logger.warning("Baseline scheduler already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        
        logger.info("Baseline scheduler started")
    
    def stop(self):
        """Stop the baseline scheduler gracefully"""
        if not self.running:
            return
        
        logger.info("Stopping baseline scheduler...")
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=10)
        
        logger.info("Baseline scheduler stopped")
    
    def _run_loop(self):
        """Main loop that runs in background thread"""
        logger.info("Baseline scheduler loop started")
        
        while self.running:
            try:
                # Check if update is needed
                if self._should_update():
                    logger.info("Starting scheduled baseline update")
                    self._update_baselines()
                    self.last_update = datetime.now()
                    logger.info("Scheduled baseline update completed")
                
            except Exception as e:
                logger.error("Error in baseline update", error=str(e), exc_info=True)
            
            # Wait before next check (check every hour)
            if self.running:
                time.sleep(3600)  # Check every hour
        
        logger.info("Baseline scheduler loop ended")
    
    def _should_update(self) -> bool:
        """Check if baseline update is needed"""
        if self.last_update is None:
            return True
        
        time_since_update = datetime.now() - self.last_update
        return time_since_update.total_seconds() >= self.update_interval
    
    def _update_baselines(self):
        """Update baselines using historical data"""
        try:
            self.baseline_manager.update_all_baselines(
                historical_days=self.historical_days
            )
            logger.info("Baselines updated successfully")
        except Exception as e:
            logger.error("Failed to update baselines", error=str(e))
            raise
