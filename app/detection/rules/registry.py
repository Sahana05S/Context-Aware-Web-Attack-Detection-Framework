"""
Rule registry for managing enabled detection rules.
Provides centralized rule management and enable/disable capabilities.
"""
from typing import List
from .base import BaseRule
from .builtin import BUILTIN_RULES


class RuleRegistry:
    """
    Registry of detection rules.
    Manages which rules are enabled and provides rule lookup.
    """
    
    def __init__(self):
        """Initialize registry with builtin rules"""
        self._all_rules: dict[str, BaseRule] = {}
        self._enabled_rule_ids: set[str] = set()
        
        # Register all builtin rules
        for rule in BUILTIN_RULES:
            self.register_rule(rule)
            # Enable by default
            self.enable_rule(rule.rule_id)
    
    def register_rule(self, rule: BaseRule) -> None:
        """
        Register a rule in the registry.
        
        Args:
            rule: Rule instance to register
        """
        self._all_rules[rule.rule_id] = rule
    
    def enable_rule(self, rule_id: str) -> None:
        """
        Enable a rule by ID.
        
        Args:
            rule_id: Rule identifier
        """
        if rule_id in self._all_rules:
            self._enabled_rule_ids.add(rule_id)
    
    def disable_rule(self, rule_id: str) -> None:
        """
        Disable a rule by ID.
        
        Args:
            rule_id: Rule identifier
        """
        self._enabled_rule_ids.discard(rule_id)
    
    def get_enabled_rules(self) -> List[BaseRule]:
        """
        Get list of all enabled rules.
        
        Returns:
            List of enabled BaseRule instances
        """
        return [
            self._all_rules[rule_id]
            for rule_id in self._enabled_rule_ids
            if rule_id in self._all_rules
        ]
    
    def get_all_rules(self) -> List[BaseRule]:
        """
        Get list of all registered rules (enabled or disabled).
        
        Returns:
            List of all BaseRule instances
        """
        return list(self._all_rules.values())
    
    def get_rule(self, rule_id: str) -> BaseRule | None:
        """
        Get specific rule by ID.
        
        Args:
            rule_id: Rule identifier
        
        Returns:
            BaseRule instance or None if not found
        """
        return self._all_rules.get(rule_id)
    
    def is_enabled(self, rule_id: str) -> bool:
        """
        Check if a rule is enabled.
        
        Args:
            rule_id: Rule identifier
        
        Returns:
            True if rule is enabled, False otherwise
        """
        return rule_id in self._enabled_rule_ids


# Global singleton registry
_registry: RuleRegistry | None = None


def get_registry() -> RuleRegistry:
    """
    Get global rule registry instance (singleton).
    
    Returns:
        RuleRegistry instance
    """
    global _registry
    if _registry is None:
        _registry = RuleRegistry()
    return _registry
