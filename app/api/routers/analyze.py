"""
AI Analysis API router — on-demand LLM-powered request analysis.
POST /api/v1/analyze
GET  /api/v1/analyze/flow/{ip}
"""
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/analyze", tags=["ai-analysis"])


class AnalyzeRequest(BaseModel):
    """Request body for on-demand analysis."""
    url:         str = Field(..., max_length=2048, description="URL to analyze")
    method:      str = Field("GET", description="HTTP method")
    status:      int = Field(200, description="HTTP status code")
    remote_ip:   str = Field("0.0.0.0", description="Client IP")
    user_agent:  Optional[str] = Field(None, max_length=512)
    body_bytes:  Optional[int] = Field(0)
    request_time: Optional[float] = Field(0.0)


class FlowSummary(BaseModel):
    """Summary of an IP's request flow."""
    remote_ip:        str
    session_count:    int
    total_events:     int
    recent_sequence:  List[dict]
    violations:       List[dict]


@router.post("")
async def analyze_request_endpoint(body: AnalyzeRequest):
    """
    Perform AI-powered intent analysis on a request.
    Uses LLM (Groq/Llama3) with heuristic fallback.
    """
    try:
        from app.detection.ai.analyzer import get_analyzer
        from app.models import LogEvent
        from datetime import datetime, timezone

        # Build a synthetic LogEvent for analysis
        event = LogEvent(
            timestamp    = datetime.now(timezone.utc),
            remote_ip    = body.remote_ip,
            method       = body.method,
            url          = body.url,
            status       = body.status,
            user_agent   = body.user_agent or "",
            body_bytes_sent = body.body_bytes or 0,
            request_time = body.request_time or 0.0,
        )

        analyzer = get_analyzer()
        result = analyzer.analyze(event)

        return {
            "success": True,
            "input": {
                "url":    body.url[:200],
                "method": body.method,
                "status": body.status,
                "ip":     body.remote_ip,
            },
            "analysis": result
        }

    except Exception as e:
        logger.error(f"On-demand analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/flow/{ip}")
async def get_flow_analysis(ip: str):
    """
    Get request flow analysis and workflow violations for an IP.
    """
    try:
        from app.detection.flow.session import get_flow_store
        from app.detection.flow.detector import detect_flow_violations

        store = get_flow_store()
        state = store.get_state(ip)

        if state is None:
            return {
                "success": True,
                "remote_ip": ip,
                "message": "No flow data for this IP",
                "session_count": 0,
                "total_events": 0,
                "recent_sequence": [],
                "violations": []
            }

        # Get recent events
        recent = state.get_recent_sequence(window_seconds=120)
        sequence = [
            {
                "timestamp": e.timestamp.isoformat(),
                "path":      e.path,
                "method":    e.method,
                "status":    e.status,
            }
            for e in recent[-20:]  # last 20 events
        ]

        # Detect violations
        violations = detect_flow_violations(ip, store)
        violations_out = [
            {
                "violation_id": v.violation_id,
                "name":        v.name,
                "severity":    v.severity,
                "confidence":  v.confidence,
                "evidence":    v.evidence,
                "sequence":    v.sequence[:8],
            }
            for v in violations
        ]

        return {
            "success":        True,
            "remote_ip":      ip,
            "session_count":  state.session_count,
            "total_events":   len(state.events),
            "recent_sequence": sequence,
            "violations":     violations_out
        }

    except Exception as e:
        logger.error(f"Flow analysis failed for {ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Flow analysis failed: {str(e)}")


@router.get("/status")
async def ai_status():
    """Check AI analyzer status and model availability."""
    try:
        from app.detection.ai.analyzer import get_analyzer
        analyzer = get_analyzer()
        return {
            "ai_enabled":    analyzer.llm_available,
            "model":         "groq/llama-3.1-8b-instant" if analyzer.llm_available else "heuristic",
            "cache_size":    len(getattr(analyzer, '_cache', {})),
            "status":        "ready"
        }
    except Exception as e:
        return {"ai_enabled": False, "model": "heuristic", "status": "error", "detail": str(e)}
