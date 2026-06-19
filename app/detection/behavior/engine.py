"""
Behavioral detection engine - SOC-style behavioral analysis.
Implements 6 behavioral flags for per-IP anomaly detection.
"""
import logging
from typing import List, Optional
from datetime import datetime, timedelta
from app.models import LogEvent
from app.core.config import settings
from app.detection.utils.urltools import normalize_for_matching
from .state import IPActivityStore
from .models import BehaviorMatch, BehaviorSeverity

logger = logging.getLogger(__name__)


# Static asset extensions to filter out (reduce noise)
STATIC_ASSET_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", 
    ".ico", ".woff", ".woff2", ".ttf", ".map"
}


def is_static_asset_path(path: str) -> bool:
    """
    Check if path points to a static asset.
    
    Args:
        path: Request path
    
    Returns:
        True if path has static asset extension
    
    Security:
        - Bounded operation (simple string check)
    """
    if not path:
        return False
    
    # Get last segment and check extension
    path_lower = path.lower()
    for ext in STATIC_ASSET_EXTENSIONS:
        if path_lower.endswith(ext):
            return True
    
    return False


def check_ip_burst_10s(
    ip: str,
    events: List[dict],
    threshold: int
) -> Optional[BehaviorMatch]:
    """
    Detect IP request burst in 10 seconds.
    
    Args:
        ip: IP address
        events: Events in 10s window
        threshold: Request count threshold
    
    Returns:
        BehaviorMatch if triggered, None otherwise
    """
    if len(events) > threshold:
        # Extract top paths for evidence
        path_counts = {}
        for event in events:
            path = event["path"]
            path_counts[path] = path_counts.get(path, 0) + 1
        
        top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        top_paths_str = ", ".join(f"{p}({c})" for p, c in top_paths)
        
        severity = BehaviorSeverity.HIGH if len(events) > threshold * 2 else BehaviorSeverity.MEDIUM
        
        return BehaviorMatch(
            flag_id="ip_burst_10s",
            name="IP Request Burst (10s)",
            severity=severity,
            confidence=0.80,
            tags=["burst", "dos", "abuse"],
            evidence=f"{len(events)} reqs in 10s: {top_paths_str}",
            fields_used=["timestamp", "path"],
            window_seconds=10
        )
    
    return None


def check_ip_burst_60s(
    ip: str,
    events: List[dict],
    threshold: int
) -> Optional[BehaviorMatch]:
    """
    Detect IP request burst in 60 seconds.
    
    Args:
        ip: IP address
        events: Events in 60s window
        threshold: Request count threshold
    
    Returns:
        BehaviorMatch if triggered, None otherwise
    """
    if len(events) > threshold:
        return BehaviorMatch(
            flag_id="ip_burst_60s",
            name="IP Request Burst (60s)",
            severity=BehaviorSeverity.MEDIUM,
            confidence=0.70,
            tags=["burst", "abuse"],
            evidence=f"{len(events)} reqs in 60s",
            fields_used=["timestamp"],
            window_seconds=60
        )
    
    return None


def check_endpoint_scan_60s(
    ip: str,
    events: List[dict],
    threshold: int
) -> Optional[BehaviorMatch]:
    """
    Detect endpoint scanning (many unique paths in 60s).
    
    Args:
        ip: IP address
        events: Events in 60s window
        threshold: Unique path count threshold
    
    Returns:
        BehaviorMatch if triggered, None otherwise
    """
    # Filter out static assets if configured
    if settings.ignore_static_assets:
        filtered_events = [e for e in events if not is_static_asset_path(e["path"])]
    else:
        filtered_events = events
    
    unique_paths = set(event["path"] for event in filtered_events)
    
    if len(unique_paths) > threshold:
        # Sample paths for evidence
        sample_paths = sorted(unique_paths)[:5]
        paths_str = ", ".join(sample_paths)
        
        severity = BehaviorSeverity.HIGH if len(unique_paths) > threshold * 2 else BehaviorSeverity.MEDIUM
        
        return BehaviorMatch(
            flag_id="endpoint_scan_60s",
            name="Endpoint Scan (60s)",
            severity=severity,
            confidence=0.85,
            tags=["scan", "reconnaissance", "abuse"],
            evidence=f"{len(unique_paths)} unique paths: {paths_str}...",
            fields_used=["path"],
            window_seconds=60
        )
    
    return None


def check_high_404_rate_60s(
    ip: str,
    events: List[dict],
    threshold: int
) -> Optional[BehaviorMatch]:
    """
    Detect high 404 error rate in 60 seconds.
    
    Args:
        ip: IP address
        events: Events in 60s window
        threshold: 404 count threshold
    
    Returns:
        BehaviorMatch if triggered, None otherwise
    """
    # Filter 404 errors
    errors_404 = [e for e in events if e["status"] == 404]
    
    # Filter out static assets if configured
    if settings.ignore_static_assets:
        errors_404 = [e for e in errors_404 if not is_static_asset_path(e["path"])]
    
    if len(errors_404) > threshold:
        # Sample 404 paths
        error_paths = [e["path"] for e in errors_404[:5]]
        paths_str = ", ".join(error_paths)
        
        return BehaviorMatch(
            flag_id="high_404_rate_60s",
            name="High 404 Rate (60s)",
            severity=BehaviorSeverity.MEDIUM,
            confidence=0.75,
            tags=["scan", "probe", "abuse"],
            evidence=f"{len(errors_404)} 404s: {paths_str}...",
            fields_used=["status", "path"],
            window_seconds=60
        )
    
    return None


def check_login_bruteforce_5m(
    ip: str,
    events: List[dict],
    threshold: int
) -> Optional[BehaviorMatch]:
    """
    Detect login brute force in 5 minutes.
    
    Args:
        ip: IP address
        events: Events in 5min window
        threshold: Failed login count threshold
    
    Returns:
        BehaviorMatch if triggered, None otherwise
    """
    # Login-related paths
    login_keywords = ['login', 'signin', 'auth']
    
    # Determine which status codes indicate failed auth
    if settings.include_redirects_in_auth:
        # Include 302 redirects on login paths (may indicate auth rejection)
        failed_statuses = {401, 403, 302}
    else:
        # Standard failed auth status codes
        failed_statuses = {401, 403}
    
    # Failed login attempts
    failed_logins = [
        e for e in events
        if (e["status"] in failed_statuses) and
        any(kw in e["path"].lower() for kw in login_keywords)
    ]
    
    if len(failed_logins) > threshold:
        # Get unique login paths
        login_paths = set(e["path"] for e in failed_logins)
        paths_str = ", ".join(sorted(login_paths)[:3])
        
        return BehaviorMatch(
            flag_id="login_bruteforce_5m",
            name="Login Brute Force (5min)",
            severity=BehaviorSeverity.HIGH,
            confidence=0.85,
            tags=["bruteforce", "auth-attack", "credential-stuffing"],
            evidence=f"{len(failed_logins)} failed logins on {paths_str}",
            fields_used=["status", "path"],
            window_seconds=300
        )
    
    return None


def check_automation_or_missing_ua(
    ip: str,
    events: List[dict]
) -> Optional[BehaviorMatch]:
    """
    Detect automation tools or missing user agent.
    
    Args:
        ip: IP address
        events: Recent events
    
    Returns:
        BehaviorMatch if triggered, None otherwise
    """
    # Check most recent event's UA
    if not events:
        return None
    
    recent_event = events[-1]
    ua = recent_event.get("normalized_ua", "")
    
    # Missing UA
    if not ua or ua.strip() == "":
        return BehaviorMatch(
            flag_id="automation_or_missing_ua",
            name="Automation or Missing UA",
            severity=BehaviorSeverity.MEDIUM,
            confidence=0.60,
            tags=["automation", "tool", "suspicious-ua"],
            evidence="Missing User-Agent",
            fields_used=["user_agent"],
            window_seconds=60
        )
    
    # Suspicious tool UAs
    suspicious_tools = ['curl', 'python-requests', 'go-http-client', 'wget', 'java/']
    
    for tool in suspicious_tools:
        if tool in ua:
            return BehaviorMatch(
                flag_id="automation_or_missing_ua",
                name="Automation or Missing UA",
                severity=BehaviorSeverity.MEDIUM,
                confidence=0.60,
                tags=["automation", "tool", "suspicious-ua"],
                evidence=f"Tool UA: {tool}",
                fields_used=["user_agent"],
                window_seconds=60
            )
    
    return None


def calculate_dynamic_threshold(
    events: List[dict],
    static_threshold: int,
    window_seconds: int,
    multiplier: float = 3.0
) -> int:
    """
    Calculate dynamic threshold based on baseline traffic.
    
    Args:
        events: Recent events for IP
        static_threshold: Static threshold value
        window_seconds: Detection window in seconds
        multiplier: Scaling multiplier (default: 3x median rate)
    
    Returns:
        Dynamic threshold (max of static threshold and baseline-scaled value)
    
    Security:
        - Bounded calculations
        - Hard caps to prevent abuse
    """
    if not events or len(events) < settings.baseline_min_events:
        return static_threshold
    
    # Calculate median requests per second over last 5 minutes
    try:
        # Get time range
        timestamps = [e["timestamp"] for e in events if "timestamp" in e]
        if len(timestamps) < 2:
            return static_threshold
        
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        if time_span <= 0:
            return static_threshold
        
        # Calculate median RPS
        median_rps = len(events) / time_span
        
        # Scale to window
        dynamic_value = int(median_rps * window_seconds * multiplier)
        
        # Use max of static and dynamic, with hard cap at 10x static
        hard_cap = static_threshold * 10
        return min(max(static_threshold, dynamic_value), hard_cap)
    
    except Exception as e:
        logger.error(f"Error calculating dynamic threshold: {e}")
        return static_threshold


def check_ip_behavior(
    ip: str,
    state_store: IPActivityStore,
    current_time: Optional[datetime] = None
) -> List[BehaviorMatch]:
    """
    Check all behavioral flags for an IP.
    
    Args:
        ip: IP address
        state_store: Activity store
        current_time: Reference time (defaults to now)
    
    Returns:
        List of triggered BehaviorMatch flags
    """
    if current_time is None:
        current_time = datetime.now()
    
    matches = []
    
    try:
        # Get events for different windows
        events_10s = state_store.get_events(ip, 10, current_time)
        events_60s = state_store.get_events(ip, 60, current_time)
        events_5m = state_store.get_events(ip, 300, current_time)
        
        # Calculate dynamic thresholds if baseline mode enabled
        if settings.baseline_mode:
            burst_10s_thresh = calculate_dynamic_threshold(
                events_5m, settings.burst_10s_threshold, 10
            )
            burst_60s_thresh = calculate_dynamic_threshold(
                events_5m, settings.burst_60s_threshold, 60
            )
            scan_thresh = calculate_dynamic_threshold(
                events_5m, settings.scan_60s_threshold, 60
            )
            high404_thresh = calculate_dynamic_threshold(
                events_5m, settings.high_404_threshold, 60
            )
            bruteforce_thresh = calculate_dynamic_threshold(
                events_5m, settings.bruteforce_5m_threshold, 300
            )
        else:
            # Use static thresholds
            burst_10s_thresh = settings.burst_10s_threshold
            burst_60s_thresh = settings.burst_60s_threshold
            scan_thresh = settings.scan_60s_threshold
            high404_thresh = settings.high_404_threshold
            bruteforce_thresh = settings.bruteforce_5m_threshold
        
        # Check burst flags
        match = check_ip_burst_10s(ip, events_10s, burst_10s_thresh)
        if match:
            matches.append(match)
        
        match = check_ip_burst_60s(ip, events_60s, burst_60s_thresh)
        if match:
            matches.append(match)
        
        # Check scan flags
        match = check_endpoint_scan_60s(ip, events_60s, scan_thresh)
        if match:
            matches.append(match)
        
        match = check_high_404_rate_60s(ip, events_60s, high404_thresh)
        if match:
            matches.append(match)
        
        # Check brute force
        match = check_login_bruteforce_5m(ip, events_5m, bruteforce_thresh)
        if match:
            matches.append(match)
        
        # Check automation (uses recent events)
        match = check_automation_or_missing_ua(ip, events_60s)
        if match:
            matches.append(match)
    
    except Exception as e:
        logger.error(f"Error checking behavior for IP {ip}: {e}")
    
    return matches


def run_behavior_detection(
    events: List[LogEvent],
    state_store: IPActivityStore
) -> dict:
    """
    Run behavioral detection on events.
    
    Args:
        events: List of log events
        state_store: Activity store
    
    Returns:
        Dict with per-IP detections:
        {
            "detections": [{"remote_ip": str, "flags": [BehaviorMatch, ...]}],
            "statistics": {...}
        }
    """
    # Update state with new events
    current_time = datetime.now()
    
    for event in events:
        # Normalize UA for matching
        normalized_ua = normalize_for_matching(event.user_agent or "", max_len=256)
        
        state_store.add_event(
            remote_ip=event.remote_ip,
            timestamp=event.timestamp,
            path=event.url.split('?')[0][:512],  # Just path, no query
            status=event.status,
            method=event.method,  # Already a string due to use_enum_values=True
            normalized_ua=normalized_ua
        )
    
    # Evict inactive IPs
    state_store.evict_inactive(current_time)
    
    # Collect unique IPs from recent events
    unique_ips = set(event.remote_ip for event in events)
    
    # Check behavior for each IP
    detections = []
    all_matches = []
    
    for ip in unique_ips:
        matches = check_ip_behavior(ip, state_store, current_time)
        if matches:
            detections.append({
                "remote_ip": ip,
                "flags": [match.model_dump() for match in matches]
            })
            all_matches.extend(matches)
    
    # Calculate statistics
    statistics = {
        "ips_flagged": len(detections),
        "total_flags": len(all_matches),
        "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
        "flag_counts": {}
    }
    
    for match in all_matches:
        severity = match.severity  # Already a string due to use_enum_values=True
        statistics["severity_counts"][severity] = statistics["severity_counts"].get(severity, 0) + 1
        
        flag_id = match.flag_id
        statistics["flag_counts"][flag_id] = statistics["flag_counts"].get(flag_id, 0) + 1
    
    return {
        "detections": detections,
        "statistics": statistics
    }
