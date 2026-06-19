"""
Pydantic schemas for API responses.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class StatusResponse(BaseModel):
    status: str
    db_status: str
    version: str = "1.0.0"

class AlertSummary(BaseModel):
    id: int
    remote_ip: str
    severity: str
    risk_score: int
    title: str
    summary: str
    status: str
    created_at: str  # ISO string from DB
    context_reasons: Optional[str] = None
    url: Optional[str] = None
    user_agent: Optional[str] = None
    ai_explanation: Optional[str] = None
    signal_breakdown: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertSummary]

class TrendPoint(BaseModel):
    bucket: str
    event_count: int
    avg_risk: float
    peak_risk: int

class OverviewStats(BaseModel):
    period_minutes: int
    alert_counts: Dict[str, int]
    top_ips: List[Dict[str, Any]]
    attack_types: Dict[str, int]
    risk_trend: List[TrendPoint]

class FlagSummary(BaseModel):
    flag_id: str
    severity: str

class AlertMini(BaseModel):
    severity: str
    title: str
    created_at: str

class IPDetail(BaseModel):
    remote_ip: str
    total_events_24h: int
    triggered_flags: List[FlagSummary]
    recent_alerts: List[AlertMini]
