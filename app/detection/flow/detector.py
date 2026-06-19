"""
Request flow / workflow violation detector.
Detects anomalous request sequences and workflow bypasses:
  - Auth bypass (accessing protected paths without auth flow)
  - Privilege escalation patterns (user → admin in one hop)
  - Rapid sensitive endpoint access
  - Abnormal navigation sequences
"""
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from .session import FlowSessionStore, IPFlowState, FlowEvent

logger = logging.getLogger(__name__)

# Paths that indicate authentication completion
AUTH_PATHS = {"/login", "/signin", "/auth", "/api/auth/token", "/api/v1/auth/token", "/oauth"}

# Paths considered sensitive / privileged
SENSITIVE_PATHS = {
    "/admin", "/dashboard", "/api/v1/admin", "/api/admin",
    "/config", "/settings", "/user/manage", "/users",
    "/export", "/download", "/backup", "/debug",
}

# API paths that shouldn't be accessed without prior auth flow
API_SENSITIVE = {"/api/v1/alerts", "/api/v1/stats", "/api/v1/ips"}

# Minimum normal browsing time between sensitive accesses (seconds)
MIN_NORMAL_DWELL = 2.0


@dataclass
class FlowViolation:
    """Detected workflow violation."""
    violation_id:  str
    name:          str
    severity:      str   # LOW / MEDIUM / HIGH / CRITICAL
    confidence:    float
    evidence:      str
    sequence:      List[str] = field(default_factory=list)  # path sequence that triggered


def detect_auth_bypass(state: IPFlowState) -> Optional[FlowViolation]:
    """
    Detect direct access to sensitive paths without prior authentication.
    Workflow violation: no login path seen, but sensitive path accessed.
    """
    session_events = state.get_session_sequence()
    if len(session_events) < 2:
        return None

    # Check if any sensitive path was accessed
    session_paths = [e.path for e in session_events]
    sensitive_accessed = [p for p in session_paths if any(sp in p.lower() for sp in SENSITIVE_PATHS)]

    if not sensitive_accessed:
        return None

    # Check if any auth path was seen BEFORE the sensitive access
    has_auth = any(any(ap in e.path.lower() for ap in AUTH_PATHS) for e in session_events)

    if not has_auth and len(session_events) <= 5:
        # Straight to sensitive paths with no auth — suspicious
        return FlowViolation(
            violation_id="auth_bypass_attempt",
            name="Auth Bypass Attempt",
            severity="HIGH",
            confidence=0.78,
            evidence=f"Accessed {sensitive_accessed[0]} without auth flow in {len(session_events)}-step session",
            sequence=session_paths[-5:],
        )
    return None


def detect_privilege_escalation(state: IPFlowState) -> Optional[FlowViolation]:
    """
    Detect rapid jump from low-privilege to admin paths.
    E.g.: /products → /admin → /admin/users in quick succession.
    """
    events = state.get_recent_sequence(window_seconds=60)
    if len(events) < 3:
        return None

    paths = [e.path.lower() for e in events]
    admin_indices = [i for i, p in enumerate(paths) if "/admin" in p or "/manage" in p]

    if not admin_indices:
        return None

    # Check if there's a rapid jump (no dwell time between non-admin and admin)
    for idx in admin_indices:
        if idx > 0:
            time_diff = (events[idx].timestamp - events[idx - 1].timestamp).total_seconds()
            prev_path = paths[idx - 1]

            # Very fast transition to admin from non-admin path
            if time_diff < MIN_NORMAL_DWELL and "/admin" not in prev_path:
                return FlowViolation(
                    violation_id="privilege_escalation_pattern",
                    name="Privilege Escalation Pattern",
                    severity="HIGH",
                    confidence=0.72,
                    evidence=f"Jumped from '{prev_path}' to '{paths[idx]}' in {time_diff:.1f}s",
                    sequence=paths[max(0, idx-2):idx+3],
                )
    return None


def detect_rapid_sensitive_access(state: IPFlowState) -> Optional[FlowViolation]:
    """
    Detect machine-speed access to multiple sensitive API endpoints.
    Humans don't enumerate API endpoints in rapid succession.
    """
    events = state.get_recent_sequence(window_seconds=30)
    if len(events) < 4:
        return None

    sensitive_events = [
        e for e in events
        if any(sp in e.path.lower() for sp in API_SENSITIVE | SENSITIVE_PATHS)
    ]

    if len(sensitive_events) < 3:
        return None

    # Calculate average time between sensitive accesses
    if len(sensitive_events) >= 2:
        time_span = (sensitive_events[-1].timestamp - sensitive_events[0].timestamp).total_seconds()
        avg_gap = time_span / (len(sensitive_events) - 1) if len(sensitive_events) > 1 else 0

        if avg_gap < 1.5:  # Less than 1.5s between each sensitive access
            paths_str = " → ".join(e.path for e in sensitive_events[:4])
            return FlowViolation(
                violation_id="rapid_sensitive_access",
                name="Rapid Sensitive Endpoint Enumeration",
                severity="HIGH",
                confidence=0.82,
                evidence=f"{len(sensitive_events)} sensitive paths in {time_span:.1f}s (avg {avg_gap:.1f}s gap): {paths_str[:200]}",
                sequence=[e.path for e in sensitive_events[:6]],
            )
    return None


def detect_scraping_pattern(state: IPFlowState) -> Optional[FlowViolation]:
    """
    Detect systematic scraping: sequential numeric IDs or regular pattern traversal.
    E.g.: /user/1, /user/2, /user/3, ... (IDOR enumeration)
    """
    events = state.get_recent_sequence(window_seconds=120)
    if len(events) < 5:
        return None

    import re
    numeric_id_pattern = re.compile(r'/(\d+)(?:/|$|\?)')

    # Collect numeric IDs accessed
    ids_seen = []
    base_paths = []
    for e in events:
        match = numeric_id_pattern.search(e.path)
        if match:
            ids_seen.append(int(match.group(1)))
            base_path = e.path[:match.start() + 1]
            base_paths.append(base_path)

    if len(ids_seen) < 4:
        return None

    # Check if IDs are sequential (IDOR enumeration)
    sorted_ids = sorted(ids_seen)
    sequential_count = sum(
        1 for i in range(len(sorted_ids) - 1)
        if sorted_ids[i+1] - sorted_ids[i] <= 2
    )

    if sequential_count >= 3:
        return FlowViolation(
            violation_id="idor_enumeration",
            name="IDOR / Sequential ID Enumeration",
            severity="HIGH",
            confidence=0.85,
            evidence=f"Sequential numeric IDs accessed: {sorted_ids[:8]} (IDOR pattern)",
            sequence=[e.path for e in events[-5:]],
        )
    return None


def detect_flow_violations(
    ip: str,
    store: FlowSessionStore,
) -> List[FlowViolation]:
    """
    Run all flow-based detectors for an IP.

    Args:
        ip: IP address to check
        store: Flow session store

    Returns:
        List of detected workflow violations
    """
    violations = []
    state = store.get_state(ip)
    if state is None:
        return violations

    try:
        # Auth bypass
        v = detect_auth_bypass(state)
        if v:
            violations.append(v)

        # Privilege escalation
        v = detect_privilege_escalation(state)
        if v:
            violations.append(v)

        # Rapid sensitive access
        v = detect_rapid_sensitive_access(state)
        if v:
            violations.append(v)

        # IDOR enumeration
        v = detect_scraping_pattern(state)
        if v:
            violations.append(v)

    except Exception as e:
        logger.error(f"Flow detection error for {ip}: {e}")

    return violations
