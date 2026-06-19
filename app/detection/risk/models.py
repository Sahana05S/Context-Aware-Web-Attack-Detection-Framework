"""
Risk scoring models and contracts.
Locked output schema for risk assessment results.
"""
from typing import List, Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class RiskSeverity(str, Enum):
    """Risk severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskResult(BaseModel):
    """
    Locked risk assessment contract.
    
    This is the stable output schema consumed by downstream modules.
    
    Fields:
        risk_score: Integer 0-100 representing overall risk
        severity: Categorical severity based on risk_score bands
        confidence: Float 0-1 representing confidence in assessment
        reasons: Top 5 explanatory strings (sanitized, <=120 chars each)
        signals: Dict summarizing individual signal contributions
        correlation: Dict with correlation context (IP, window, counts)
    
    Severity Bands:
        0-19: LOW
        20-49: MEDIUM
        50-79: HIGH
        80-100: CRITICAL
    """
    
    risk_score: int = Field(ge=0, le=100, description="Risk score 0-100")
    severity: RiskSeverity = Field(description="Risk severity level")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence 0-1")
    reasons: List[str] = Field(max_length=5, description="Top 5 reasons, sanitized")
    signals: Dict[str, Any] = Field(description="Signal contributions summary")
    correlation: Dict[str, Any] = Field(description="Correlation context")
    ai_explanation: Optional[str] = Field(None, description="Plain English AI explanation")
    what_was_detected: Optional[str] = Field(None, description="Specific detected payload/action")
    
    @field_validator('reasons')
    @classmethod
    def validate_reasons(cls, v: List[str]) -> List[str]:
        """Validate reasons are sanitized and bounded"""
        if len(v) > 5:
            raise ValueError("Maximum 5 reasons allowed")
        
        for reason in v:
            if len(reason) > 120:
                raise ValueError(f"Reason too long (>120 chars): {reason[:50]}...")
            # Check for control characters
            if not all(c.isprintable() or c.isspace() for c in reason):
                raise ValueError(f"Reason contains non-printable characters")
        
        return v
    
    @field_validator('risk_score')
    @classmethod
    def validate_risk_score(cls, v: int) -> int:
        """Ensure risk_score in bounds"""
        return max(0, min(100, v))
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence in bounds"""
        return max(0.0, min(1.0, v))
