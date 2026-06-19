"""
Dashboard-ready query functions.
Read-only access to detection data for API/UI.
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta
from app.core.config import settings
from .db import get_db_connection


def _stmt(query: str) -> str:
    """Helper to format placeholders according to DATABASE_TYPE"""
    if settings.DATABASE_TYPE == "postgresql":
        return query.replace('?', '%s')
    return query


def _get_since_time_str(since_minutes: int) -> str:
    """Compute since_time ISO string in UTC"""
    since_time = datetime.utcnow() - timedelta(minutes=since_minutes)
    return since_time.strftime("%Y-%m-%d %H:%M:%S")


def get_recent_alerts(limit: int = 50, offset: int = 0, since_minutes: int = 60) -> List[Dict[str, Any]]:
    """Get recent alerts with pagination"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    since_time_str = _get_since_time_str(since_minutes)
    
    cursor.execute(_stmt("""
        SELECT 
            a.id, a.event_id, a.remote_ip, a.severity, a.risk_score, a.title, a.summary, a.status, a.created_at,
            a.url, a.user_agent, a.ai_explanation, a.signal_breakdown,
            r.reasons_json as context_reasons
        FROM alerts a
        LEFT JOIN risk_results r ON a.event_id = r.event_id
        WHERE a.created_at >= ?
        ORDER BY a.created_at DESC
        LIMIT ? OFFSET ?
    """), (since_time_str, limit, offset))
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_recent_alerts_count(since_minutes: int = 60) -> int:
    """Get total count of alerts in time window"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    since_time_str = _get_since_time_str(since_minutes)
    
    cursor.execute(_stmt("""
        SELECT COUNT(*)
        FROM alerts
        WHERE created_at >= ?
    """), (since_time_str,))
    
    return cursor.fetchone()[0]


def get_alert_counts_by_severity(since_minutes: int = 1440) -> Dict[str, int]:
    """Get alert counts grouped by severity"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    since_time_str = _get_since_time_str(since_minutes)
    
    cursor.execute(_stmt("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE created_at >= ?
        GROUP BY severity
    """), (since_time_str,))
    
    return {row[0]: row[1] for row in cursor.fetchall()}


def get_top_attacking_ips(limit: int = 10, since_minutes: int = 1440) -> List[Dict[str, Any]]:
    """Get top IPs by alert count/risk"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    since_time_str = _get_since_time_str(since_minutes)
    
    cursor.execute(_stmt("""
        SELECT 
            remote_ip, 
            COUNT(*) as high_risk_events,
            MAX(risk_score) as max_risk
        FROM risk_results r
        JOIN events e ON r.event_id = e.id
        WHERE r.created_at >= ?
          AND r.risk_score >= 20
        GROUP BY remote_ip
        ORDER BY high_risk_events DESC
        LIMIT ?
    """), (since_time_str, limit))
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_attack_type_distribution(since_minutes: int = 1440) -> Dict[str, int]:
    """Get distribution of attack types from rule matches"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    since_time_str = _get_since_time_str(since_minutes)
    
    cursor.execute(_stmt("""
        SELECT attack_type, COUNT(*) as count
        FROM rule_matches
        WHERE created_at >= ?
          AND attack_type IS NOT NULL
        GROUP BY attack_type
    """), (since_time_str,))
    
    return {row[0]: row[1] for row in cursor.fetchall()}


def get_risk_trend(bucket_minutes: int = 60, since_hours: int = 24) -> List[Dict[str, Any]]:
    """Get average risk score per time bucket"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    since_time_str = _get_since_time_str(since_hours * 60)
    
    if settings.DATABASE_TYPE == "postgresql":
        # PostgreSQL time aggregation
        query = """
            SELECT 
                TO_CHAR(created_at, 'YYYY-MM-DD HH24:00:00') as bucket,
                COUNT(*) as event_count,
                AVG(risk_score) as avg_risk,
                MAX(risk_score) as peak_risk
            FROM risk_results
            WHERE created_at >= %s
            GROUP BY bucket
            ORDER BY bucket ASC
        """
        cursor.execute(query, (since_time_str,))
    else:
        # SQLite time aggregation
        query = """
            SELECT 
                strftime('%Y-%m-%d %H:00:00', created_at) as bucket,
                COUNT(*) as event_count,
                AVG(risk_score) as avg_risk,
                MAX(risk_score) as peak_risk
            FROM risk_results
            WHERE created_at >= ?
            GROUP BY bucket
            ORDER BY bucket ASC
        """
        cursor.execute(query, (since_time_str,))
    
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def get_ip_detail(remote_ip: str, since_hours: int = 24) -> Dict[str, Any]:
    """Get detailed view for an IP"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    since_time_str = _get_since_time_str(since_hours * 60)
    
    # 1. Summary stats
    cursor.execute(_stmt("""
        SELECT COUNT(*) as total_events
        FROM events
        WHERE remote_ip = ? AND created_at >= ?
    """), (remote_ip, since_time_str))
    total_events = cursor.fetchone()[0]
    
    # 2. Recent alerts
    cursor.execute(_stmt("""
        SELECT severity, title, created_at
        FROM alerts
        WHERE remote_ip = ? AND created_at >= ?
        ORDER BY created_at DESC
        LIMIT 5
    """), (remote_ip, since_time_str))
    recent_alerts = [dict(zip(['severity', 'title', 'created_at'], row)) for row in cursor.fetchall()]
    
    # 3. Triggered flags (distinct)
    cursor.execute(_stmt("""
        SELECT DISTINCT flag_id, severity
        FROM behavior_flags
        WHERE remote_ip = ? AND created_at >= ?
    """), (remote_ip, since_time_str))
    flags = [dict(zip(['flag_id', 'severity'], row)) for row in cursor.fetchall()]
    
    return {
        "remote_ip": remote_ip,
        "total_events_24h": total_events,
        "recent_alerts": recent_alerts,
        "triggered_flags": flags
    }
