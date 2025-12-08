"""
Networks API Router
Provides endpoints for network discovery and network-specific statistics
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any

from storage.db_manager import DuckDBManager

router = APIRouter(prefix="/networks", tags=["networks"])

def get_db_manager():
    """Get database manager instance"""
    return DuckDBManager(db_path="data/logs.duckdb")

@router.get("", response_model=List[str])
async def get_networks():
    """
    Get list of all unique network IDs present in the system
    
    Returns:
        List of network IDs
    """
    try:
        db_manager = get_db_manager()
        networks = db_manager.get_networks()
        return networks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{network_id}/stats")
async def get_network_stats(network_id: str):
    """
    Get statistics for a specific network
    
    Args:
        network_id: Network identifier
        
    Returns:
        Network-specific statistics
    """
    try:
        db_manager = get_db_manager()
        
        # Count logs for this network
        total_logs = db_manager.count_logs(network_id=network_id)
        
        # Count alerts for this network (we'll need to add network_id to alerts too)
        # For now, just get all alerts and filter by host
        alerts = db_manager.fetch_alerts(limit=10000)
        
        # Get logs to find hosts in this network
        logs = db_manager.fetch_logs(limit=1000, network_id=network_id)
        network_hosts = list(set([log.host for log in logs if log.host]))
        
        # Filter alerts by hosts in this network
        network_alerts = [a for a in alerts if a.host in network_hosts]
        
        return {
            "network_id": network_id,
            "total_logs": total_logs,
            "total_alerts": len(network_alerts),
            "hosts": network_hosts,
            "host_count": len(network_hosts)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
