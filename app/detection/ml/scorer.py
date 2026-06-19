"""
ML Scorer with heuristic fallback.
Works immediately without trained model.
"""
import logging
from typing import Dict, Optional, Any
from pathlib import Path
from app.models import LogEvent
from .features import extract_features

logger = logging.getLogger(__name__)


class MLScorer:
    """
    ML-based attack scorer with heuristic fallback.
    
    Features:
        - Heuristic scoring (no model required)
        - Optional model-based scoring
        - Explainable results
    """
    
    def __init__(self):
        """Initialize scorer"""
        self.model = None
        self.vectorizer = None
        self.model_loaded = False
        
        # Try to load model artifacts
        try:
            from .model import load_artifacts
            self.vectorizer, self.model = load_artifacts()
            self.model_loaded = True
            logger.info("ML model loaded successfully")
        except Exception as e:
            logger.info(f"ML model not available, using heuristic fallback: {e}")
            self.model_loaded = False
    
    def _sanitize_explanation(self, text: str) -> str:
        """
        Sanitize explanation string.
        
        Security:
            - Remove CRLF and control characters
            - Bound to 120 chars
        """
        # Remove CR, LF, and other control characters
        sanitized = ''.join(c for c in text if c.isprintable())
        # Bound length
        return sanitized[:120]
    
    def _heuristic_score(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Heuristic scoring when model unavailable.
        
        Args:
            features: Extracted features
        
        Returns:
            Score dict with score, label, explanation, model_used
        
        Security:
            - Bounded calculations
            - Capped final score to [0, 1]
            - Sanitized explanation
        """
        score = 0.05  # Base score
        reasons = []
        
        # SQL injection indicators (bounded)
        sql_count = min(features.get('count_sql_keywords', 0), 10)
        if sql_count > 0:
            weight = min(sql_count * 0.15, 0.30)
            score += weight
            reasons.append(f"{sql_count} SQL keywords")
        
        # XSS indicators (bounded)
        xss_count = min(features.get('count_xss_tokens', 0), 10)
        if xss_count > 0:
            weight = min(xss_count * 0.15, 0.30)
            score += weight
            reasons.append(f"{xss_count} XSS tokens")
        
        # Path traversal indicators (bounded)
        traversal_count = min(features.get('count_traversal_tokens', 0), 10)
        if traversal_count > 0:
            weight = min(traversal_count * 0.10, 0.20)
            score += weight
            reasons.append(f"{traversal_count} traversal patterns")
        
        # Command injection indicators (bounded)
        cmd_count = min(features.get('count_cmd_tokens', 0), 10)
        if cmd_count > 0:
            weight = min(cmd_count * 0.10, 0.20)
            score += weight
            reasons.append(f"{cmd_count} cmd tokens")
        
        # Suspicious UA
        if features.get('is_suspicious_ua', 0) == 1:
            score += 0.10
            reasons.append("suspicious UA")
        
        # High special char ratio
        if features.get('special_char_ratio', 0) > 0.3:
            score += 0.05
            reasons.append("high special chars")
        
        # Many percent-encoded chars
        if features.get('pct_encoded', 0) > 10:
            score += 0.05
            reasons.append("many encoded chars")
        
        # Cap score to [0, 1]
        score = max(0.0, min(1.0, score))
        
        # Determine label
        if score < 0.3:
            label = "LOW"
        elif score < 0.7:
            label = "MEDIUM"
        else:
            label = "HIGH"
        
        # Build explanation
        if reasons:
            explanation = f"Heuristic: {', '.join(reasons[:5])}"  # Top 5 reasons
        else:
            explanation = "Heuristic: normal traffic pattern"
        
        return {
            "ml_score": round(score, 3),
            "ml_label": label,
            "explanation": self._sanitize_explanation(explanation),
            "model_used": False
        }
    
    def _model_score(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Model-based scoring when model available.
        
        Args:
            features: Extracted features
        
        Returns:
            Score dict with score, label, explanation, model_used
        """
        try:
            from .model import predict_proba
            
            # Get probability from model
            proba = predict_proba(self.vectorizer, self.model, features)
            
            # Determine label
            if proba < 0.3:
                label = "LOW"
            elif proba < 0.7:
                label = "MEDIUM"
            else:
                label = "HIGH"
            
            # Extract top contributing features for explanation
            # Simple heuristic: show features with highest values
            top_features = sorted(
                [(k, v) for k, v in features.items() if v > 0],
                key=lambda x: x[1],
                reverse=True
            )[:3]
            
            if top_features:
                feature_names = [f"{k}={v}" for k, v in top_features]
                explanation = f"Model: {', '.join(feature_names)}"
            else:
                explanation = "Model: no significant patterns"
            
            return {
                "ml_score": round(proba, 3),
                "ml_label": label,
                "explanation": self._sanitize_explanation(explanation),
                "model_used": True
            }
        
        except Exception as e:
            logger.error(f"Model scoring failed, using heuristic: {e}")
            return self._heuristic_score(features)
    
    def score_event(self, event: LogEvent, derived: dict) -> Dict[str, Any]:
        """
        Score a log event for maliciousness.
        
        Args:
            event: LogEvent to score
            derived: Derived context (from rule engine)
        
        Returns:
            Dict with ml_score (0-1), ml_label (LOW/MEDIUM/HIGH), explanation, model_used
        
        Output Contract (locked):
            - ml_score: float (0.0-1.0)
            - ml_label: "LOW" | "MEDIUM" | "HIGH"
            - explanation: string (<=120 chars, sanitized)
            - model_used: boolean
        
        Security:
            - Fail-safe: always returns valid result
            - Bounded operations
            - Sanitized output
            - Never crashes pipeline
        """
        try:
            # Extract features
            features = extract_features(event, derived)
            
            # Score using model or heuristic
            if self.model_loaded and self.model is not None:
                result = self._model_score(features)
            else:
                result = self._heuristic_score(features)
            
            return result
        
        except Exception as e:
            logger.error(f"Scoring failed: {e}")
            # Fail-safe: return minimal score
            return {
                "ml_score": 0.05,
                "ml_label": "LOW",
                "explanation": self._sanitize_explanation("Error during scoring"),
                "model_used": False
            }
