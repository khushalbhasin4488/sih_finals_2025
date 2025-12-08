from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Any
from datetime import datetime

from storage.db_manager import DuckDBManager
from analytics.engine import AnalyticsEngine

router = APIRouter(prefix="/analytics", tags=["analytics"])

# Dependency to get analytics engine
def get_analytics_engine():
    # In a real app, you might use dependency injection or a global singleton properly
    # For now, we instantiate with the global DB path
    db_manager = DuckDBManager(db_path="data/logs.duckdb")
    return AnalyticsEngine(db_manager)

@router.get("/overview", response_model=Dict[str, Any])
async def get_analytics_overview(
    time_range_minutes: int = Query(1440, description="Lookback window in minutes"),
    network: str = Query(None, description="Filter by network ID"),
    engine: AnalyticsEngine = Depends(get_analytics_engine)
):
    """
    Get comprehensive log analytics overview
    spanning volume, performance, errors, security, and users.
    """
    try:
        return engine.get_overview_stats(time_range_minutes, network_id=network)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
