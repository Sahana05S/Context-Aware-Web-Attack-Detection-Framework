"""
Risk scoring engine.
Combines signals from rules, behavior, ML, and context to produce risk assessment.
"""
import logging
from typing import List, Dict, Any, Optional
from app.models import LogEvent
from .models import RiskResult, RiskSeverity
from .weights import (
    RULE_WEIGHT_CAP, BEHAVIOR_WEIGHT_CAP, ML_WEIGHT_CAP, CONTEXT_WEIGHT_CAP,
    AI_WEIGHT_CAP, AI_SCORE_WEIGHTS, FLOW_VIOLATION_BONUS,
    RULE_SEVERITY_WEIGHTS, BEHAVIOR_SEVERITY_WEIGHTS, ML_LABEL_WEIGHTS,
    CONTEXT_SENSITIVITY_WEIGHTS, SEVERITY_BANDS,
    BASE_CONFIDENCE, MULTI_SIGNAL_AGREEMENT_BOOST, ALL_SIGNALS_BOOST
)
from .explain import (
    build_rule_reason, build_behavior_reason, build_ml_reason,
    build_context_reason, build_correlation_reason, select_top_reasons
)

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Risk scoring engine that correlates multiple signals.
    
    Combines:
    - Rule matches (dominant, up to 0.55)
    - Behavior anomalies (secondary, up to 0.30)
    - ML predictions (probability contributor, up to 0.15)
    - Context (endpoint sensitivity, up to 0.10)
    
    Outputs deterministic, explainable RiskResult.
    """
    
    def __init__(self):
        """Initialize risk engine"""
        pass

    def _compute_ai_component(
        self,
        ai_output: dict,
        reasons: list
    ) -> float:
        """
        Compute AI analyzer contribution (0 to AI_WEIGHT_CAP=0.12).
        AI provides contextual intent analysis beyond pattern matching.
        """
        if not ai_output:
            return 0.0

        ai_score = ai_output.get("ai_score", 0.0)
        severity = ai_output.get("severity", "LOW")
        is_attack = ai_output.get("is_attack", False)
        explanation = ai_output.get("explanation", "")
        attack_type = ai_output.get("attack_type", "Normal")
        zero_day = ai_output.get("zero_day_risk", False)

        if not is_attack:
            return 0.0

        weight = AI_SCORE_WEIGHTS.get(severity, 0.10)
        component = min(weight * AI_WEIGHT_CAP, AI_WEIGHT_CAP)

        if component > 0.02:
            model = ai_output.get("model_used", "heuristic")
            reason_text = f"AI ({model}): {attack_type}"
            if zero_day:
                reason_text += " [zero-day risk]"
            if explanation:
                reason_text += f" — {explanation[:100]}"
            reasons.append(reason_text)

        return component
    
    def _compute_rule_component(
        self,
        rule_matches: List[Dict[str, Any]],
        reasons: List[str]
    ) -> float:
        """
        Compute rule contribution (0 to RULE_WEIGHT_CAP).
        
        Args:
            rule_matches: List of rule match dicts
            reasons: List to append reasons to
        
        Returns:
            Rule component score (0 to 0.55)
        """
        if not rule_matches:
            return 0.0
        
        # Find highest severity match
        max_weight = 0.0
        top_match = None
        
        for match in rule_matches[:10]:  # Cap at 10 matches for performance
            severity = match.get('severity', 'LOW')
            weight = RULE_SEVERITY_WEIGHTS.get(severity, 0.0)
            if weight > max_weight:
                max_weight = weight
                top_match = match
        
        # Scale to rule cap
        component = min(max_weight * RULE_WEIGHT_CAP, RULE_WEIGHT_CAP)
        
        # Add reason
        if top_match:
            reasons.append(build_rule_reason(top_match))
        
        return component
    
    def _compute_behavior_component(
        self,
        behavior_matches: List[Dict[str, Any]],
        reasons: List[str]
    ) -> float:
        """
        Compute behavior contribution (0 to BEHAVIOR_WEIGHT_CAP).
        
        Args:
            behavior_matches: List of behavior match dicts
            reasons: List to append reasons to
        
        Returns:
            Behavior component score (0 to 0.30)
        """
        if not behavior_matches:
            return 0.0
        
        # Find highest severity match
        max_weight = 0.0
        top_match = None
        
        for match in behavior_matches[:10]:
            severity = match.get('severity', 'LOW')
            weight = BEHAVIOR_SEVERITY_WEIGHTS.get(severity, 0.0)
            if weight > max_weight:
                max_weight = weight
                top_match = match
        
        # Scale to behavior cap
        component = min(max_weight * BEHAVIOR_WEIGHT_CAP, BEHAVIOR_WEIGHT_CAP)
        
        # Add reason
        if top_match:
            reasons.append(build_behavior_reason(top_match))
        
        return component
    
    def _compute_ml_component(
        self,
        ml_output: Dict[str, Any],
        reasons: List[str]
    ) -> float:
        """
        Compute ML contribution (0 to ML_WEIGHT_CAP).
        
        ML is a probability contributor, never primary authority.
        
        Args:
            ml_output: ML scoring dict
            reasons: List to append reasons to
        
        Returns:
            ML component score (0 to 0.15)
        """
        if not ml_output:
            return 0.0
        
        ml_label = ml_output.get('ml_label', 'LOW')
        weight = ML_LABEL_WEIGHTS.get(ml_label, 0.0)
        
        # Scale to ML cap (secondary role)
        component = min(weight * ML_WEIGHT_CAP, ML_WEIGHT_CAP)
        
        # Add reason if significant
        if weight > 0.2:
            reasons.append(build_ml_reason(ml_output))
        
        return component
    
    def _compute_context_component(
        self,
        derived: Dict[str, Any],
        reasons: List[str]
    ) -> float:
        """
        Compute context contribution (0 to CONTEXT_WEIGHT_CAP).
        
        Checks for sensitive endpoint indicators in path.
        
        Args:
            derived: Derived context dict
            reasons: List to append reasons to
        
        Returns:
            Context component score (0 to 0.10)
        """
        path = derived.get('path', '').lower()
        
        # Check for sensitive keywords
        for keyword, weight in CONTEXT_SENSITIVITY_WEIGHTS.items():
            if keyword in path:
                # Scale to context cap
                component = min(weight * CONTEXT_WEIGHT_CAP / 0.10, CONTEXT_WEIGHT_CAP)
                reasons.append(build_context_reason(keyword))
                return component
        
        return 0.0
    
    def _compute_correlation_context(
        self,
        event: LogEvent,
        derived: Dict[str, Any],
        reasons: List[str]
    ) -> Dict[str, Any]:
        """
        Compute correlation context from behavioral state if available.
        
        Args:
            event: Log event
            derived: Derived context
            reasons: List to append reasons to
        
        Returns:
            Correlation dict with IP, window, counts
        """
        if not event:
            return {
                "remote_ip": "0.0.0.0",
                "window_seconds": 0,
                "event_count": 0,
                "distinct_paths": 0
            }

        correlation = {
            "remote_ip": event.remote_ip,
            "window_seconds": 0,
            "event_count": 1,
            "distinct_paths": 1
        }
        
        # Try to get from behavior store if available
        try:
            from app.detection.behavior.state import get_activity_store
            store = get_activity_store()
            
            # Get recent events for this IP
            events_60s = store.get_events(event.remote_ip, window_seconds=60)
            
            if len(events_60s) > 1:
                correlation["window_seconds"] = 60
                correlation["event_count"] = len(events_60s)
                
                # Count distinct paths
                paths = set(e.get('path', '') for e in events_60s)
                correlation["distinct_paths"] = len(paths)
                
                # Add reason if significant activity
                if len(events_60s) > 10 or len(paths) > 5:
                    reasons.append(build_correlation_reason(correlation))
        
        except Exception as e:
            logger.debug(f"Could not compute correlation context: {e}")
        
        return correlation
    
    def _compute_confidence(
        self,
        rule_component: float,
        behavior_component: float,
        ml_component: float,
        context_component: float
    ) -> float:
        """
        Compute confidence based on signal agreement.
        
        Args:
            rule_component: Rule contribution
            behavior_component: Behavior contribution
            ml_component: ML contribution
            context_component: Context contribution
        
        Returns:
            Confidence float (0-1)
        """
        confidence = BASE_CONFIDENCE
        
        # Count active signals (threshold > 0.05)
        active_signals = sum([
            1 if rule_component > 0.05 else 0,
            1 if behavior_component > 0.05 else 0,
            1 if ml_component > 0.05 else 0,
            1 if context_component > 0.05 else 0
        ])
        
        # Boost for multiple signals
        if active_signals >= 2:
            confidence += MULTI_SIGNAL_AGREEMENT_BOOST
        
        if active_signals >= 3:
            confidence += ALL_SIGNALS_BOOST
        
        # Cap to [0, 1]
        return max(0.0, min(1.0, confidence))
    
    def _map_severity(self, risk_score: int) -> RiskSeverity:
        """
        Map risk score to severity band.
        
        Args:
            risk_score: Integer 0-100
        
        Returns:
            RiskSeverity enum
        """
        for severity, (low, high) in SEVERITY_BANDS.items():
            if low <= risk_score <= high:
                return RiskSeverity(severity)
        
        return RiskSeverity.LOW
    
    def score_event(
        self,
        event: LogEvent,
        rule_matches: list,
        behavior_matches: list,
        ml_output: dict,
        derived: dict,
        ai_output: dict = None,
        flow_violations: list = None,
    ) -> 'RiskResult':
        """
        Score an event considering all signals including AI and flow.

        Args:
            event: Log event to score
            rule_matches: List of rule match dicts
            behavior_matches: List of behavior match dicts
            ml_output: ML scoring dict
            derived: Derived context dict
            ai_output: Optional AI analyzer output dict
            flow_violations: Optional list of FlowViolation objects

        Returns:
            RiskResult with complete risk assessment
        """
        try:
            reasons = []
            ai_output      = ai_output or {}
            flow_violations = flow_violations or []

            # Compute components
            rule_component     = self._compute_rule_component(rule_matches, reasons)
            behavior_component = self._compute_behavior_component(behavior_matches, reasons)
            ml_component       = self._compute_ml_component(ml_output, reasons)
            context_component  = self._compute_context_component(derived, reasons)
            ai_component       = self._compute_ai_component(ai_output, reasons)

            # Aggregate (capped at 1.0)
            total_score = min(
                1.0,
                rule_component
                + behavior_component
                + ml_component
                + context_component
                + ai_component
            )

            # Multi-match bonus
            from .weights import MULTI_MATCH_BONUS_PER_RULE, MULTI_MATCH_MAX_BONUS
            if len(rule_matches) > 1:
                bonus_pts = min(
                    (len(rule_matches) - 1) * MULTI_MATCH_BONUS_PER_RULE,
                    MULTI_MATCH_MAX_BONUS
                )
                reasons.append(f"Multi-vector attack: {len(rule_matches)} rule signatures matched (+{bonus_pts} pts)")
            else:
                bonus_pts = 0

            # Flow violation bonus
            flow_bonus = 0
            if flow_violations:
                flow_bonus = min(len(flow_violations) * FLOW_VIOLATION_BONUS, 20)
                for v in flow_violations[:2]:
                    reasons.append(f"Workflow violation: {v.name} — {v.evidence[:80]}")

            # Convert to 0-100
            risk_score = round(total_score * 100) + bonus_pts + flow_bonus
            risk_score = max(0, min(100, risk_score))

            # Map to severity
            severity = self._map_severity(risk_score)

            # Compute confidence (now includes AI signal)
            confidence = self._compute_confidence(
                rule_component,
                behavior_component,
                ml_component,
                context_component + ai_component,  # treat AI as part of context layer
            )

            # Get correlation context
            correlation = self._compute_correlation_context(event, derived, reasons)

            # Build signals summary
            signals = {
                "rule_component":      round(rule_component, 3),
                "behavior_component":  round(behavior_component, 3),
                "ml_component":        round(ml_component, 3),
                "context_component":   round(context_component, 3),
                "ai_component":        round(ai_component, 3),
                "multi_match_bonus":   bonus_pts,
                "flow_violation_bonus": flow_bonus,
                "total":               round(total_score, 3)
            }

            top_reasons = select_top_reasons(reasons, max_count=5)
            if not top_reasons:
                top_reasons = ["Normal traffic pattern"]

            return RiskResult(
                risk_score  = risk_score,
                severity    = severity,
                confidence  = confidence,
                reasons     = top_reasons,
                signals     = signals,
                correlation = correlation,
                ai_explanation = ai_output.get("plain_english"),
                what_was_detected = ai_output.get("what_was_detected")
            )

        except Exception as e:
            logger.error(f"Risk scoring failed: {e}")
            return RiskResult(
                risk_score  = 0,
                severity    = RiskSeverity.LOW,
                confidence  = 0.5,
                reasons     = ["Error during risk scoring"],
                signals     = {"error": str(e)[:100]},
                correlation = {"remote_ip": event.remote_ip if event else "0.0.0.0"}
            )

