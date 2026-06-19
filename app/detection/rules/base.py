"""
Base interface for detection rules.
All rules must inherit from BaseRule and implement the match() method.
"""
from abc import ABC, abstractmethod
from typing import Optional
from app.models import LogEvent
from .models import RuleMatch, Severity


class BaseRule(ABC):
    """
    Abstract base class for all detection rules.
    
    Rules are stateless and thread-safe.
    Each rule defines its own detection logic via match().
    """
    
    def __init__(self):
        """Initialize rule with metadata"""
        self.rule_id: str = self.get_rule_id()
        self.name: str = self.get_name()
        self.severity: Severity = self.get_severity()
        self.tags: list[str] = self.get_tags()
    
    @abstractmethod
    def get_rule_id(self) -> str:
        """Return unique rule identifier (e.g., 'sqli_union_select')"""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Return human-readable rule name"""
        pass
    
    @abstractmethod
    def get_severity(self) -> Severity:
        """Return rule severity level"""
        pass
    
    @abstractmethod
    def get_tags(self) -> list[str]:
        """Return classification tags (e.g., ['sqli', 'injection', 'web'])"""
        pass
    
    @abstractmethod
    def match(self, event: LogEvent, derived: dict) -> Optional[RuleMatch]:
        """
        Check if this rule matches the given event.
        
        Args:
            event: Normalized log event
            derived: Derived context (decoded URLs, normalized strings, etc.)
        
        Returns:
            RuleMatch if detection triggers, None otherwise
        
        Security:
            - Must not throw exceptions (fail-safe)
            - Must cap processing time/resources
            - Must sanitize evidence before returning
        """
        pass
    
    def _create_match(
        self,
        confidence: float,
        evidence: str,
        fields_used: list[str]
    ) -> RuleMatch:
        """
        Helper to create a RuleMatch instance.
        
        Args:
            confidence: Detection confidence (0.0-1.0)
            evidence: Evidence string (will be sanitized)
            fields_used: List of event fields used in detection
        
        Returns:
            RuleMatch instance
        
        Security:
            Defense-in-depth: Sanitizes evidence here AND in RuleMatch validation
        """
        # Defensive sanitization (defense-in-depth)
        # Remove CRLF, null bytes, and control characters
        sanitized_evidence = ''.join(
            char for char in evidence
            if ord(char) >= 0x20 and ord(char) != 0x7f and char not in '\r\n\x00'
        )
        # Truncate to 120 chars
        sanitized_evidence = sanitized_evidence[:120]
        
        return RuleMatch(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            confidence=confidence,
            tags=self.tags,
            evidence=sanitized_evidence,
            fields_used=fields_used
        )
