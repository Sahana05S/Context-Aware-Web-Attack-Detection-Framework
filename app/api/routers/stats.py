"""
Statistics router.
"""
from fastapi import APIRouter, Query
from app.api.schemas import OverviewStats
from app.storage import (
    get_alert_counts_by_severity,
    get_top_attacking_ips,
    get_attack_type_distribution,
    get_risk_trend
)
from app.detection.ai.summarizer import generate_dashboard_summary

router = APIRouter()

@router.get("/stats/overview", response_model=OverviewStats)
def get_overview_stats(
    since_minutes: int = Query(1440, ge=60, le=10080)
):
    """
    Get overview statistics for dashboard.
    """
    return OverviewStats(
        period_minutes=since_minutes,
        alert_counts=get_alert_counts_by_severity(since_minutes=since_minutes),
        top_ips=get_top_attacking_ips(limit=10, since_minutes=since_minutes),
        attack_types=get_attack_type_distribution(since_minutes=since_minutes),
        risk_trend=[
            {
                "bucket": t["bucket"],
                "event_count": t["event_count"],
                "avg_risk": t["avg_risk"],
                "peak_risk": t["peak_risk"]
            }
            for t in get_risk_trend(bucket_minutes=60, since_hours=max(1, since_minutes // 60))
        ]
    )

@router.get("/stats/ai-summary")
def get_ai_summary(since_minutes: int = Query(1440, ge=60, le=10080)):
    """
    Get AI-generated morning briefing summary of the SOC stats.
    """
    stats = {
        "alert_counts": get_alert_counts_by_severity(since_minutes=since_minutes),
        "top_ips": get_top_attacking_ips(limit=3, since_minutes=since_minutes),
        "attack_types": get_attack_type_distribution(since_minutes=since_minutes),
    }
    summary = generate_dashboard_summary(stats)
    return {"summary": summary}
