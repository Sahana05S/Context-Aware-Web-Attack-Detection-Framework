"""
Shared event processor for the ingest pipeline.
Wraps the detection engine for single-event use by both Upload and Live routers.
"""
import logging
from app.models import LogEvent

logger = logging.getLogger(__name__)


def process_single_event(event: LogEvent, commit: bool = True) -> dict:
    """
    Run a single LogEvent through the full detection pipeline:
    rules → behavior → ML → risk scoring → storage.

    Returns the detection result dict (may be empty if no rules matched).
    Fail-safe: exceptions are caught and logged without crashing the caller.
    """
    try:
        from app.detection.rules.registry import get_registry
        from app.detection.rules.engine import run_on_events, derive_context
        from app.detection.behavior.state import get_activity_store
        from app.detection.behavior.engine import run_behavior_detection
        from app.detection.ml import MLScorer
        from app.detection.risk import RiskEngine
        from app.storage.service import get_storage_service

        # 1. Rule-based detection
        rules = get_registry().get_enabled_rules()
        rule_results = run_on_events([event], rules)
        matches = rule_results[0].get("matches", []) if rule_results else []

        # 2. Behavioral detection (uses shared singleton state)
        activity_store = get_activity_store()
        behavior_result = run_behavior_detection([event], activity_store)
        behavior_matches = []
        for d in behavior_result.get("detections", []):
            if d.get("remote_ip") == event.remote_ip:
                behavior_matches = d.get("flags", [])
                break

        # 3. ML scoring — use proper derived context from derive_context()
        derived = derive_context(event)
        scorer = MLScorer()
        ml_output = scorer.score_event(event, derived)

        # 4. AI Judge scoring (conditional to save API calls)
        from app.detection.ai import analyze_request
        ai_output = {}
        if matches or behavior_matches or ml_output.get("ml_score", 0) > 0.3:
            ai_output = analyze_request(event, matches, behavior_matches)

        # 5. Risk scoring — call score_event() with correct arguments
        risk_engine = RiskEngine()
        risk_result = risk_engine.score_event(
            event=event,
            rule_matches=matches,
            behavior_matches=behavior_matches,
            ml_output=ml_output,
            derived=derived,
            ai_output=ai_output,
        )
        risk_dict = risk_result.model_dump()

        # 6. Persist to database
        storage = get_storage_service()
        storage.store_detection_result(
            event=event,
            matches=matches,
            behavior_matches=behavior_matches,
            ml_output=ml_output,
            risk_result=risk_dict,
            derived=derived,
            commit=commit
        )

        return {"risk": risk_dict, "matches": matches}

    except Exception as e:
        logger.error(f"Detection pipeline failed for {event.remote_ip}: {e}", exc_info=True)
        return {}
