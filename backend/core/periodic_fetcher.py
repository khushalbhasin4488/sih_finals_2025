"""
Periodic log fetcher - fetches logs at regular intervals
"""
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Callable, List
import structlog

from storage.db_manager import DuckDBManager
from storage.models import LogEntry

logger = structlog.get_logger()


class PeriodicLogFetcher:
    """
    Fetches logs from DuckDB at regular intervals
    Designed to work with the existing microservice that ingests logs every ~1 minute
    """
    
    def __init__(
        self,
        db_manager: DuckDBManager,
        interval_seconds: int = 60,
        batch_size: int = 10000
    ):
        """
        Initialize periodic log fetcher
        
        Args:
            db_manager: DuckDB manager instance
            interval_seconds: Interval between fetches (default: 60 seconds)
            batch_size: Maximum logs to fetch per cycle
        """
        self.db_manager = db_manager
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self.last_fetch_time: Optional[datetime] = None
        self.is_running = False
        self.callbacks: List[Callable[[List[LogEntry]], None]] = []
        
        logger.info(
            "Periodic log fetcher initialized",
            interval=interval_seconds,
            batch_size=batch_size
        )
    
    def register_callback(self, callback: Callable[[List[LogEntry]], None]):
        """
        Register a callback to be called with fetched logs
        
        Args:
            callback: Function that accepts List[LogEntry]
        """
        self.callbacks.append(callback)
        logger.info("Callback registered", callback=callback.__name__)
    
    async def fetch_cycle(self) -> List[LogEntry]:
        """
        Execute one fetch cycle
        
        Returns:
            List of fetched logs
        """
        try:
            # Calculate time range
            end_time = datetime.now()
            
            if self.last_fetch_time is None:
                # First fetch - get logs from last interval
                start_time = end_time - timedelta(seconds=self.interval_seconds)
            else:
                # Subsequent fetches - get logs since last fetch
                start_time = self.last_fetch_time
            
            # Fetch logs
            logs = self.db_manager.fetch_logs(
                start_time=start_time,
                end_time=end_time,
                limit=self.batch_size
            )
            
            # Update last fetch time
            self.last_fetch_time = end_time
            
            logger.info(
                "Fetch cycle completed",
                logs_fetched=len(logs),
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat()
            )
            
            # Call registered callbacks
            for callback in self.callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(logs)
                    else:
                        callback(logs)
                except Exception as e:
                    logger.error(
                        "Error in callback",
                        callback=callback.__name__,
                        error=str(e)
                    )
            
            return logs
            
        except Exception as e:
            logger.error("Error in fetch cycle", error=str(e))
            raise
    
    async def start(self):
        """Start periodic fetching"""
        self.is_running = True
        logger.info("Periodic log fetcher started")
        
        while self.is_running:
            try:
                await self.fetch_cycle()
                
                # Wait for next interval
                await asyncio.sleep(self.interval_seconds)
                
            except Exception as e:
                logger.error("Error in fetch loop", error=str(e))
                # Continue running even if there's an error
                await asyncio.sleep(self.interval_seconds)
    
    def stop(self):
        """Stop periodic fetching"""
        self.is_running = False
        logger.info("Periodic log fetcher stopped")
    
    async def start_with_timeout(self, timeout_seconds: Optional[int] = None):
        """
        Start periodic fetching with optional timeout
        
        Args:
            timeout_seconds: Stop after this many seconds (None = run indefinitely)
        """
        if timeout_seconds:
            try:
                await asyncio.wait_for(
                    self.start(),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                logger.info("Periodic fetcher timeout reached")
                self.stop()
        else:
            await self.start()


async def example_callback(logs: List[LogEntry]):
    """Example callback function"""
    logger.info(
        "Example callback received logs",
        count=len(logs)
    )
    
    # Process logs here
    for log in logs[:5]:  # Print first 5
        logger.info(
            "Log entry",
            timestamp=log.timestamp,
            host=log.host,
            message=log.message[:50] if log.message else None
        )


async def main():
    """Example usage of periodic log fetcher"""
    from core.config import config
    
    # Initialize database manager
    db_manager = DuckDBManager(config.get_database_path())
    
    # Create periodic fetcher
    fetcher = PeriodicLogFetcher(
        db_manager=db_manager,
        interval_seconds=60,  # Fetch every 60 seconds
        batch_size=10000
    )
    
    # Register callback
    fetcher.register_callback(example_callback)
    
    # Start fetching (run for 5 minutes as example)
    try:
        await fetcher.start_with_timeout(timeout_seconds=300)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        fetcher.stop()
    finally:
        db_manager.close()


if __name__ == "__main__":
    asyncio.run(main())
