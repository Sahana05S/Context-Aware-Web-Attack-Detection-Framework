"""
Dashboard-ready query functions.
Read-only access to detection data for API/UI.
"""
from typing import List, Dict, Any
from .db import get_db_connection


def get_recent_alerts(limit: int = 50, offset: int = 0, since_minutes: int = 60) -> List[Dict[str, Any]]:
    """Get recent alerts with pagination"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            a.id, a.event_id, a.remote_ip, a.severity, a.risk_score, a.title, a.summary, a.status, a.created_at,
            a.url, a.user_agent, a.ai_explanation, a.signal_breakdown,
            r.reasons_json as context_reasons
        FROM alerts a
        LEFT JOIN risk_results r ON a.event_id = r.event_id
        WHERE a.created_at >= datetime('now', ?)
        ORDER BY a.created_at DESC
        LIMIT ? OFFSET ?
    """, (f"-{since_minutes} minutes", limit, offset))
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_recent_alerts_count(since_minutes: int = 60) -> int:
    """Get total count of alerts in time window"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE created_at >= datetime('now', ?)
    """, (f"-{since_minutes} minutes",))
    
    return cursor.fetchone()[0]


def get_alert_counts_by_severity(since_minutes: int = 1440) -> Dict[str, int]:
    """Get alert counts grouped by severity"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE created_at >= datetime('now', ?)
        GROUP BY severity
    """, (f"-{since_minutes} minutes",))
    
    return {row[0]: row[1] for row in cursor.fetchall()}


def get_top_attacking_ips(limit: int = 10, since_minutes: int = 1440) -> List[Dict[str, Any]]:
    """Get top IPs by alert count/risk"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Simple heuristic: Count of high-risk events per IP
    cursor.execute("""
        SELECT 
            remote_ip, 
            COUNT(*) as high_risk_events,
            MAX(risk_score) as max_risk
        FROM risk_results r
        JOIN events e ON r.event_id = e.id
        WHERE r.created_at >= datetime('now', ?)
          AND r.risk_score >= 20
        GROUP BY remote_ip
        ORDER BY high_risk_events DESC
        LIMIT ?
    """, (f"-{since_minutes} minutes", limit))
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_attack_type_distribution(since_minutes: int = 1440) -> Dict[str, int]:
    """Get distribution of attack types from rule matches"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM rule_matches
        WHERE created_at >= datetime('now', ?)
          AND attack_type IS NOT NULL
        GROUP BY attack_type
    """, (f"-{since_minutes} minutes",))
    
    return {row[0]: row[1] for row in cursor.fetchall()}


def get_risk_trend(bucket_minutes: int = 60, since_hours: int = 24) -> List[Dict[str, Any]]:
    """Get average risk score per time bucket"""
    # SQLite doesn't have great date truncation, so we'll fetch basic stats 
    # and might aggregate in app if complex, but here's a rough approximation
    # utilizing strftime for hourly buckets
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Bucket by hour for simplicity in this POC
    cursor.execute("""
        SELECT 
            strftime('%Y-%m-%d %H:00:00', created_at) as bucket,
            COUNT(*) as event_count,
            AVG(risk_score) as avg_risk,
            MAX(risk_score) as peak_risk
        FROM risk_results
        WHERE created_at >= datetime('now', ?)
        GROUP BY bucket
        ORDER BY bucket ASC
    """, (f"-{since_hours} hours",))
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_ip_detail(remote_ip: str, since_hours: int = 24) -> Dict[str, Any]:
    """Get detailed view for an IP"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Summary stats
    cursor.execute("""
        SELECT COUNT(*) as total_events
        FROM events
        WHERE remote_ip = ? AND created_at >= datetime('now', ?)
    """, (remote_ip, f"-{since_hours} hours"))
    total_events = cursor.fetchone()[0]
    
    # 2. Recent alerts
    cursor.execute("""
        SELECT severity, title, created_at
        FROM alerts
        WHERE remote_ip = ? AND created_at >= datetime('now', ?)
        ORDER BY created_at DESC
        LIMIT 5
    """, (remote_ip, f"-{since_hours} hours"))
    recent_alerts = [dict(zip(['severity', 'title', 'created_at'], row)) for row in cursor.fetchall()]
    
    # 3. Triggered flags (distinct)
    cursor.execute("""
        SELECT DISTINCT flag_id, severity
        FROM behavior_flags
        WHERE remote_ip = ? AND created_at >= datetime('now', ?)
    """, (remote_ip, f"-{since_hours} hours"))
    flags = [dict(zip(['flag_id', 'severity'], row)) for row in cursor.fetchall()]
    
    return {
        "remote_ip": remote_ip,
        "total_events_24h": total_events,
        "recent_alerts": recent_alerts,
        "triggered_flags": flags
    }
