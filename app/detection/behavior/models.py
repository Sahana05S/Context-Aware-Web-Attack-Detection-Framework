"""
Behavioral detection models.
Defines BehaviorMatch contract for SOC-style behavioral flags.
"""
from enum import Enum
from pydantic import BaseModel, ConfigDict, field_validator


class BehaviorSeverity(str, Enum):
    """Severity levels for behavioral detections"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class BehaviorMatch(BaseModel):
    """
    Behavioral detection result.
    
    Represents a behavioral anomaly detected for an IP address
    over a time window (e.g., request burst, brute force).
    
    Security: Immutable, evidence sanitized to prevent log injection.
    """
    model_config = ConfigDict(frozen=True, use_enum_values=True)
    
    flag_id: str
    name: str
    severity: BehaviorSeverity
    confidence: float  # 0.0-1.0
    tags: list[str]
    evidence: str  # Max 120 chars, sanitized
    fields_used: list[str]
    window_seconds: int  # Time window for detection
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Ensure confidence is between 0 and 1"""
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"Confidence must be between 0 and 1, got {v}")
        return v
    
    @field_validator('evidence')
    @classmethod
    def sanitize_evidence(cls, v: str) -> str:
        """
        Sanitize evidence to prevent log injection.
        
        Security:
            - Removes CR, LF, null bytes
            - Removes control characters
            - Truncates to 120 characters
        
        Raises:
            ValueError: If evidence contains dangerous characters
        """
        # Check for null byte
        if '\x00' in v:
            raise ValueError("Evidence contains null byte")
        
        # Check for CRLF
        if '\r' in v or '\n' in v:
            raise ValueError("Evidence contains CR or LF")
        
        # Remove control characters (< 0x20 or == 0x7F)
        sanitized = ''.join(
            char for char in v
            if ord(char) >= 0x20 and ord(char) != 0x7f
        )
        
        # Truncate to 120 chars
        return sanitized[:120]
    
    @field_validator('window_seconds')
    @classmethod
    def validate_window(cls, v: int) -> int:
        """Ensure window is positive"""
        if v <= 0:
            raise ValueError(f"Window must be positive, got {v}")
        return v
