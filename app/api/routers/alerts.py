"""
Alerts router.
"""
from typing import List, Optional
from fastapi import APIRouter, Query
from app.api.schemas import AlertSummary, AlertListResponse
from app.storage import get_recent_alerts, get_recent_alerts_count

router = APIRouter()

@router.get("/alerts", response_model=AlertListResponse)
def list_alerts(
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    since_minutes: int = Query(1440, ge=1, le=10080),
    severity: Optional[str] = None
):
    """
    Get recent alerts with pagination.
    
    Args:
        limit: Max number of alerts (default 200)
        offset: Pagination offset (default 0)
        since_minutes: Lookback window (default 24h)
        severity: Filter by severity (optional)
    """
    alerts = get_recent_alerts(limit=limit, offset=offset, since_minutes=since_minutes)
    total = get_recent_alerts_count(since_minutes=since_minutes)
    
    # Optional severity filtering in memory
    if severity:
        alerts = [a for a in alerts if a['severity'].upper() == severity.upper()]
        total = len(alerts) # update total if filtered
        
    return {"total": total, "alerts": alerts}
