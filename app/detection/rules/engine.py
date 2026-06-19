"""
Detection engine - runs rules against log events and produces detections.
Implements safe derived context generation and bounded rule execution.
"""
import logging
from typing import List, Optional
from app.models import LogEvent
from app.detection.utils.urltools import (
    split_url,
    safe_unquote,
    normalize_for_matching
)
from .base import BaseRule
from .models import RuleMatch
from app.storage import get_storage_service

logger = logging.getLogger(__name__)

# Global singletons (initialized once)
_ml_scorer: Optional['MLScorer'] = None
_behavior_engine: Optional['BehaviorEngine'] = None
_risk_engine: Optional['RiskEngine'] = None



def get_ml_scorer():
    """Get or create singleton ML scorer instance."""
    global _ml_scorer
    if _ml_scorer is None:
        try:
            from app.detection.ml import MLScorer
            _ml_scorer = MLScorer()
            logger.info("ML Scorer initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ML Scorer: {e}")
            _ml_scorer = None
    return _ml_scorer


def get_behavior_engine():
    """Get or create singleton behavior engine instance."""
    global _behavior_engine
    if _behavior_engine is None:
        try:
            from app.detection.behavior.wrapper import BehaviorEngine
            _behavior_engine = BehaviorEngine()
            logger.info("Behavior Engine initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Behavior Engine: {e}")
            _behavior_engine = None
    return _behavior_engine


def get_risk_engine():
    """Get or create singleton risk engine instance."""
    global _risk_engine
    if _risk_engine is None:
        try:
            from app.detection.risk import RiskEngine
            _risk_engine = RiskEngine()
            logger.info("Risk Engine initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Risk Engine: {e}")
            _risk_engine = None
    return _risk_engine


def derive_context(event: LogEvent) -> dict:
    """
    Derive additional context from log event for rule matching.
    
    Generates normalized and decoded variants of event fields
    to support detection of both raw and encoded attacks.
    
    Args:
        event: Normalized log event
    
    Returns:
        Dict containing derived fields:
        - path, query: Split URL components
        - decoded_url, decoded_query: URL-decoded variants
        - normalized_query, normalized_ua: Lowercased, whitespace-collapsed
        - query_len: Query string length
        - special_char_ratio: Ratio of special chars (capped calculation)
    
    Security:
        - All operations are bounded
        - Fail-safe: returns partial context on error
    """
    context = {}
    
    try:
        # Split URL into path and query
        path, query = split_url(event.url)
        context["path"] = path
        context["query"] = query
        context["query_len"] = len(query)
        
        # Decode URL components (with CRLF/null rejection)
        try:
            context["decoded_url"] = safe_unquote(event.url)
        except ValueError:
            # Rejected due to CRLF/null - use empty string
            context["decoded_url"] = ""
        
        try:
            context["decoded_query"] = safe_unquote(query)
        except ValueError:
            context["decoded_query"] = ""
        
        # Normalize for matching
        context["normalized_query"] = normalize_for_matching(query, max_len=2048)
        context["normalized_ua"] = normalize_for_matching(
            event.user_agent or "", max_len=512
        )
        
        # Calculate special character ratio (bounded)
        if query and len(query) <= 2048:
            special_chars = sum(
                1 for c in query[:2048]
                if c in "!@#$%^&*(){}[]|\\;:'\",<>?/`~"
            )
            context["special_char_ratio"] = special_chars / min(len(query), 2048)
        else:
            context["special_char_ratio"] = 0.0
        
    except Exception as e:
        logger.error(f"Error deriving context: {e}")
        # Return partial context (fail-safe)
    
    return context


def run_rules(event: LogEvent, rules: List[BaseRule]) -> List[RuleMatch]:
    """
    Run detection rules against a single event.
    
    Args:
        event: Log event to analyze
        rules: List of rules to run
    
    Returns:
        List of RuleMatch results (may be empty)
    
    Security:
        - Each rule runs in try/except (fail-safe)
        - Derived context is bounded
        - Returns only valid RuleMatch instances
    """
    matches = []
    
    # Derive context once for all rules
    derived = derive_context(event)
    
    # Run each rule
    for rule in rules:
        try:
            match = rule.match(event, derived)
            if match:
                matches.append(match)
        except Exception as e:
            logger.error(f"Error running rule {rule.rule_id}: {e}")
            # Continue with next rule (fail-safe)
    
    return matches


def run_on_events(events: List[LogEvent], rules: List[BaseRule]) -> List[dict]:
    """
    Run detection rules on multiple events.
    
    MODULE 5 INTEGRATION: Includes ML scoring for every event.
    MODULE 6 INTEGRATION: Includes behavior detection and risk scoring.
    
    Args:
        events: List of log events
        rules: List of rules to run
    
    Returns:
        List of dicts, each containing:
        - event_summary: Summary of the event
        - matches: List of RuleMatch instances
        - ml: ML scoring output
        - behavior: Behavior detection output (if matches found)
        - risk: Risk scoring output (MODULE 6)
    
    Only events with at least one match are included by default.
    """
    results = []
    
    # Get singletons
    ml_scorer = get_ml_scorer()
    behavior_engine = get_behavior_engine()
    risk_engine = get_risk_engine()
    storage_service = get_storage_service()
    
    for event in events:
        matches = run_rules(event, rules)
        
        # Only include events with matches
        if matches:
            # Create event summary
            event_summary = {
                "timestamp": str(event.timestamp),
                "remote_ip": event.remote_ip,
                "method": str(event.method),  # use_enum_values=True means method may already be str
                "url": event.url[:200],
                "status": event.status,
            }
            
            # Derive context once (shared)
            derived = derive_context(event)
            
            # MODULE 5: Get ML scoring (fail-safe)
            ml_output = {"ml_score": 0.05, "ml_label": "LOW", "explanation": "ML unavailable", "model_used": False}
            if ml_scorer:
                try:
                    ml_output = ml_scorer.score_event(event, derived)
                except Exception as e:
                    logger.error(f"ML scoring failed for event: {e}")
            
            # MODULE 6: Get behavior detection (fail-safe)
            behavior_matches = []
            if behavior_engine:
                try:
                    behavior_result = behavior_engine.check_ip_behavior(event, derived)
                    if behavior_result:
                        behavior_matches = behavior_result  # List of BehaviorMatch
                except Exception as e:
                    logger.error(f"Behavior detection failed for event: {e}")
            
            # MODULE 6: Compute risk score (fail-safe)
            risk_output = None
            if risk_engine:
                try:
                    # Convert matches to dicts for risk engine
                    rule_dicts = [m.model_dump() for m in matches]
                    behavior_dicts = [m.model_dump() for m in behavior_matches] if behavior_matches else []
                    
                    risk_result = risk_engine.score_event(
                        event=event,
                        rule_matches=rule_dicts,
                        behavior_matches=behavior_dicts,
                        ml_output=ml_output,
                        derived=derived
                    )
                    risk_output = risk_result.model_dump()
                except Exception as e:
                    logger.error(f"Risk scoring failed for event: {e}")
                    # Minimal fallback
                    risk_output = {
                        "risk_score": 0,
                        "severity": "LOW",
                        "confidence": 0.5,
                        "reasons": ["Risk scoring unavailable"],
                        "signals": {},
                        "correlation": {}
                    }
            
            # MODULE 7: Persist to storage (fail-safe)
            try:
                storage_service.store_detection_result(
                    event=event,
                    matches=[m.model_dump() for m in matches],
                    behavior_matches=[m.model_dump() for m in behavior_matches] if behavior_matches else [],
                    ml_output=ml_output,
                    risk_result=risk_output if risk_output else {},
                    derived=derived
                )
            except Exception as e:
                logger.error(f"Storage persistence failed: {e}")

            # Build result
            result = {
                "event_summary": event_summary,
                "matches": [match.model_dump() for match in matches],
                "ml": ml_output
            }
            
            # Add behavior if present
            if behavior_matches:
                result["behavior"] = [m.model_dump() for m in behavior_matches]
            
            # Add risk (MODULE 6)
            if risk_output:
                result["risk"] = risk_output
            
            results.append(result)
    
    return results


def get_detection_stats(results: List[dict]) -> dict:
    """
    Calculate detection statistics from results.
    
    Args:
        results: List of detection results from run_on_events()
    
    Returns:
        Dict with statistics:
        - total_events: Number of events analyzed
        - matched_events: Number of events with at least one match
        - severity_counts: Count by severity level
        - rule_counts: Count by rule_id
    """
    stats = {
        "total_matched_events": len(results),
        "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
        "rule_counts": {},
    }
    
    for result in results:
        for match in result["matches"]:
            # Count by severity
            severity = match["severity"]
            stats["severity_counts"][severity] = stats["severity_counts"].get(severity, 0) + 1
            
            # Count by rule_id
            rule_id = match["rule_id"]
            stats["rule_counts"][rule_id] = stats["rule_counts"].get(rule_id, 0) + 1
    
    return stats
