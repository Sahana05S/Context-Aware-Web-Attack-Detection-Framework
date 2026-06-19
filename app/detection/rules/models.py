"""
Data models for rule-based detection.
Defines detection severity levels and rule match results.
"""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class Severity(str, Enum):
    """Detection severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RuleMatch(BaseModel):
    """
    Immutable record of a rule match.
    
    Represents a single detection finding from a rule.
    Evidence is sanitized and capped for safe logging.
    """
    
    model_config = ConfigDict(frozen=True)
    
    rule_id: str = Field(..., description="Unique rule identifier", max_length=100)
    name: str = Field(..., description="Human-readable rule name", max_length=200)
    severity: Severity = Field(..., description="Detection severity level")
    confidence: float = Field(..., description="Confidence score 0.0-1.0", ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list, description="Classification tags (e.g., 'sqli', 'web')")
    evidence: str = Field(..., description="Sanitized evidence snippet", max_length=120)
    fields_used: list[str] = Field(default_factory=list, description="Log fields examined")
    
    @field_validator('evidence')
    @classmethod
    def sanitize_evidence(cls, v: str) -> str:
        """
        Sanitize evidence string.
        
        Security:
            - Remove CR, LF, null bytes
            - Truncate to 120 chars
            - Remove control characters
        """
        if not v:
            return ""
        
        # Remove dangerous characters
        if '\x00' in v:
            raise ValueError("Evidence contains null byte")
        if '\r' in v or '\n' in v:
            raise ValueError("Evidence contains CR or LF")
        
        # Remove other control characters
        sanitized = ''.join(char for char in v if ord(char) >= 0x20 and ord(char) != 0x7f)
        
        # Truncate
        return sanitized[:120]
    
    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        """Validate and cap tag list"""
        if not v:
            return []
        # Cap to 10 tags, each max 50 chars
        return [tag[:50] for tag in v[:10]]
    
    @field_validator('fields_used')
    @classmethod
    def validate_fields(cls, v: list[str]) -> list[str]:
        """Validate and cap fields list"""
        if not v:
            return []
        # Cap to 10 fields, each max 50 chars
        return [field[:50] for field in v[:10]]
