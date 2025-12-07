"""
Analysis Service
Manages the continuous orchestrator in a background thread
"""
import asyncio
import threading
import time
import structlog
from typing import Optional

logger = structlog.get_logger()


class AnalysisService:
    """
    Background service that runs the orchestrator continuously
    """
    
    def __init__(self, orchestrator, interval: int = 60):
        """
        Initialize analysis service
        
        Args:
            orchestrator: AnalysisOrchestrator instance
            interval: Analysis interval in seconds (default: 60)
        """
        self.orchestrator = orchestrator
        self.interval = interval
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        logger.info("Analysis service initialized", interval=interval)
    
    def start(self):
        """Start the analysis service in a background thread"""
        if self.running:
            logger.warning("Analysis service already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        
        logger.info("Analysis service started")
    
    def stop(self):
        """Stop the analysis service gracefully"""
        if not self.running:
            return
        
        logger.info("Stopping analysis service...")
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=10)
        
        logger.info("Analysis service stopped")
    
    def _run_loop(self):
        """Main loop that runs in background thread"""
        logger.info("Analysis service loop started")
        
        # Create event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        while self.running:
            try:
                # Run analysis cycle
                logger.debug("Running analysis cycle")
                stats = loop.run_until_complete(self.orchestrator.run_analysis_cycle())
                
                logger.info(
                    "Analysis cycle completed",
                    logs_processed=stats.get('logs_processed', 0),
                    alerts_generated=stats.get('alerts_generated', 0),
                    cycle_time=stats.get('cycle_time', 0)
                )
                
            except Exception as e:
                logger.error("Error in analysis cycle", error=str(e), exc_info=True)
            
            # Wait for next cycle
            if self.running:
                time.sleep(self.interval)
        
        loop.close()
        logger.info("Analysis service loop ended")
