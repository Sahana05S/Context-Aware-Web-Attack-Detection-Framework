"""
IP Details router.
"""
from fastapi import APIRouter, HTTPException, Path, Query
from app.api.schemas import IPDetail
from app.api.deps import verify_remote_ip
from app.storage import get_ip_detail

router = APIRouter()

@router.get("/ips/{remote_ip}", response_model=IPDetail)
def get_ip_info(
    remote_ip: str = Path(..., description="Remote IP address to inspect"),
    since_hours: int = Query(24, ge=1, le=720)
):
    """
    Get detailed information for a specific IP.
    """
    # Basic validation
    try:
        verify_remote_ip(remote_ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    details = get_ip_detail(remote_ip, since_hours=since_hours)
    
    # Check if IP has any data (total_events_24h > 0 or existing records)
    # get_ip_detail returns 0 counts if no data, which is valid.
    # We only 404 if the IP is truly invalid or we decide to strict mode.
    # For dashboard, zero data is a valid result (clean IP).
    
    return IPDetail(
        remote_ip=details['remote_ip'],
        total_events_24h=details['total_events_24h'],
        triggered_flags=[
            {"flag_id": f['flag_id'], "severity": f['severity']}
            for f in details['triggered_flags']
        ],
        recent_alerts=[
            {"severity": a['severity'], "title": a['title'], "created_at": a['created_at']}
            for a in details['recent_alerts']
        ]
    )
