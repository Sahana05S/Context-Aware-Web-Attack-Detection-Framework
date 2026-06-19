"""
Explanation and reason generation for risk scoring.
Includes sanitization helpers.
"""
from typing import List, Dict, Any


def sanitize_reason(text: str, max_len: int = 120) -> str:
    """
    Sanitize a reason string.
    
    Security:
        - Removes CR, LF, and non-printable characters
        - Bounds to max_len
    
    Args:
        text: Raw reason text
        max_len: Maximum length (default 120)
    
    Returns:
        Sanitized string
    """
    # Remove non-printable chars (keep spaces)
    sanitized = ''.join(c for c in text if c.isprintable() or c == ' ')
    # Collapse multiple spaces
    sanitized = ' '.join(sanitized.split())
    # Bound length
    return sanitized[:max_len]


def build_rule_reason(match: Dict[str, Any]) -> str:
    """
    Build reason from rule match.
    
    Args:
        match: Rule match dict with rule_id, severity
    
    Returns:
        Sanitized reason string
    """
    rule_id = str(match.get('rule_id', 'unknown'))[:30]
    severity = str(match.get('severity', 'UNKNOWN'))[:10]
    reason = f"Rule: {rule_id} ({severity})"
    return sanitize_reason(reason)


def build_behavior_reason(match: Dict[str, Any]) -> str:
    """
    Build reason from behavior match.
    
    Args:
        match: Behavior match dict with flag_id, severity
    
    Returns:
        Sanitized reason string
    """
    flag_id = str(match.get('flag_id', 'unknown'))[:30]
    severity = str(match.get('severity', 'UNKNOWN'))[:10]
    reason = f"Behavior: {flag_id} ({severity})"
    return sanitize_reason(reason)


def build_ml_reason(ml_output: Dict[str, Any]) -> str:
    """
    Build reason from ML output.
    
    Args:
        ml_output: ML dict with ml_score, ml_label, model_used
    
    Returns:
        Sanitized reason string
    """
    score = ml_output.get('ml_score', 0.0)
    label = str(ml_output.get('ml_label', 'UNKNOWN'))[:10]
    model_used = ml_output.get('model_used', False)
    reason = f"ML: {score:.2f} {label} model={model_used}"
    return sanitize_reason(reason)


def build_context_reason(context_label: str) -> str:
    """
    Build reason from context.
    
    Args:
        context_label: Context label (e.g., 'admin', 'api')
    
    Returns:
        Sanitized reason string
    """
    label = str(context_label)[:30]
    reason = f"Context: sensitive endpoint ({label})"
    return sanitize_reason(reason)


def build_correlation_reason(correlation: Dict[str, Any]) -> str:
    """
    Build reason from correlation context.
    
    Args:
        correlation: Correlation dict with event_count, distinct_paths, etc.
    
    Returns:
        Sanitized reason string
    """
    count = correlation.get('event_count', 0)
    window = correlation.get('window_seconds', 60)
    paths = correlation.get('distinct_paths', 0)
    
    if paths > 1:
        reason = f"Correlation: {count} req/{window}s, {paths} paths"
    else:
        reason = f"Correlation: {count} req/{window}s"
    
    return sanitize_reason(reason)


def select_top_reasons(all_reasons: List[str], max_count: int = 5) -> List[str]:
    """
    Select top N reasons, prioritizing non-empty and unique.
    
    Args:
        all_reasons: List of reason strings
        max_count: Maximum reasons to return
    
    Returns:
        List of top reasons (deduplicated, bounded)
    """
    # Filter non-empty
    valid_reasons = [r for r in all_reasons if r and r.strip()]
    
    # Deduplicate while preserving order
    seen = set()
    unique_reasons = []
    for reason in valid_reasons:
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)
    
    # Return top N
    return unique_reasons[:max_count]
