"""
Scoring weights and configuration for risk engine.
"""

# Component weight caps (capped individually, total can exceed 1.0 — final score is capped at 1.0)
RULE_WEIGHT_CAP     = 0.55   # Rules are dominant signal
BEHAVIOR_WEIGHT_CAP = 0.28   # Behavior anomalies second
ML_WEIGHT_CAP       = 0.10   # ML is probability contributor only
CONTEXT_WEIGHT_CAP  = 0.10   # Context/endpoint sensitivity
AI_WEIGHT_CAP       = 0.12   # AI intent analyzer (LLM/heuristic)

# Severity thresholds for different signal types
RULE_SEVERITY_WEIGHTS = {
    "LOW": 0.25,
    "MEDIUM": 0.65,   # MEDIUM rule → 0.65*0.55 = 35 pts alone → MEDIUM band
    "HIGH": 0.90,    # HIGH rule → 0.90*0.55 = 49.5 pts (+ context = HIGH)
    "CRITICAL": 1.00
}

BEHAVIOR_SEVERITY_WEIGHTS = {
    "LOW": 0.20,
    "MEDIUM": 0.55,
    "HIGH": 0.85,
    "CRITICAL": 1.00
}

# ML score bands (ml_label to weight)
ML_LABEL_WEIGHTS = {
    "LOW": 0.05,
    "MEDIUM": 0.35,
    "HIGH": 0.70
}

# Context sensitivity weights
CONTEXT_SENSITIVITY_WEIGHTS = {
    "admin": 0.10,
    "api": 0.08,
    "auth": 0.09,
    "login": 0.09,
    "payment": 0.10,
    "sensitive": 0.08,
    "default": 0.02
}

# Risk score to severity mapping
SEVERITY_BANDS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 79),
    "CRITICAL": (80, 100)
}

# Confidence boosting
BASE_CONFIDENCE = 0.5
MULTI_SIGNAL_AGREEMENT_BOOST = 0.15  # When 2+ signals agree
ALL_SIGNALS_BOOST = 0.25               # When 3+ signals present

# Multi-match bonus: extra points per additional rule match (capped)
MULTI_MATCH_BONUS_PER_RULE = 3   # +3 pts per extra match beyond 1
MULTI_MATCH_MAX_BONUS = 15       # cap at +15

# AI signal score weights
AI_SCORE_WEIGHTS = {
    "LOW":      0.10,
    "MEDIUM":   0.50,
    "HIGH":     0.85,
    "CRITICAL": 1.00
}

# Flow/workflow violation weight bonus
FLOW_VIOLATION_BONUS = 8   # extra risk points per flow violation (capped at 20)
