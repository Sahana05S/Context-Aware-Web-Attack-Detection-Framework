import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import shutil
import sqlite3
import logging
from datetime import datetime
from app.models import LogEvent
from app.core.config import settings
from app.storage import (
    get_db_connection, close_db_connection, get_storage_service,
    get_recent_alerts, get_alert_counts_by_severity,
    get_top_attacking_ips, get_attack_type_distribution,
    get_risk_trend, get_ip_detail
)

# Setup temp DB for testing
TEST_DB_PATH = "./data/test_storage.db"
settings.DATABASE_PATH = TEST_DB_PATH

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def setup_test_db():
    """Setup fresh test database"""
    close_db_connection()
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception as e:
            logger.warning(f"Failed to remove test DB: {e}")
    
    # Force connection init
    conn = get_db_connection()
    logger.info("Test database initialized")
    return conn


def test_persistence_and_alerts():
    """Test full storage flow: persist -> alert -> query"""
    print("Testing Storage Persistence & Alerts...")
    
    setup_test_db()
    service = get_storage_service()
    
    # 1. Create synthetic event
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="10.0.0.99",
        method="POST",
        url="/admin/login?user=admin'--",
        status=200,
        user_agent="Mozilla/5.0",
        referer="",
        body_bytes_sent=500,
        request_time=0.5
    )
    derived = {"path": "/admin/login", "normalized_ua": "mozilla"}
    
    # 2. Synthetic detection results (HIGH risk)
    matches = [{
        "rule_id": "sqli_001",
        "severity": "HIGH",
        "confidence": 0.9,
        "attack_type": "sqli",
        "evidence": "admin'--"
    }]
    
    behavior = [{
        "flag_id": "ip_burst_10s",
        "severity": "MEDIUM",
        "confidence": 0.8,
        "evidence": "25 reqs in 10s",
        "remote_ip": "10.0.0.99"
    }]
    
    ml_output = {
        "ml_score": 0.75,
        "ml_label": "MEDIUM",
        "explanation": "Heuristic match",
        "model_used": False
    }
    
    risk_result = {
        "risk_score": 85,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "reasons": ["Rule: sqli_001 (HIGH)", "Behavior: burst", "ML: 0.75"],
        "signals": {"rule": 0.55, "behavior": 0.25},
        "correlation": {"event_count": 10}
    }
    
    # 3. Store result
    event_id = service.store_detection_result(
        event, matches, behavior, ml_output, risk_result, derived
    )
    assert event_id is not None
    print(f"✓ Stored event ID: {event_id}")
    
    # 4. Verify tables
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check tables
    assert cursor.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert cursor.execute("SELECT COUNT(*) FROM rule_matches").fetchone()[0] == 1
    assert cursor.execute("SELECT COUNT(*) FROM behavior_flags").fetchone()[0] == 1
    assert cursor.execute("SELECT COUNT(*) FROM ml_scores").fetchone()[0] == 1
    assert cursor.execute("SELECT COUNT(*) FROM risk_results").fetchone()[0] == 1
    assert cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    print("✓ All tables populated correctly")
    
    # 5. Verify alert content
    alert = cursor.execute("SELECT * FROM alerts").fetchone()
    # (id, event_id, ip, severity, risk, title, summary, status, created)
    # Adjust index based on schema or use description
    # id=0, event=1, ip=2, severity=3, risk=4, title=5, summary=6...
    assert alert[2] == "10.0.0.99"
    assert alert[3] == "CRITICAL"
    assert alert[4] == 85
    assert "CRITICAL Risk" in alert[5]
    print(f"✓ Alert generated: {alert[5]} (Score {alert[4]})")
    
    # 6. Test dashboard queries
    print("\nTesting Dashboard Queries:")
    
    recent_alerts = get_recent_alerts(limit=5)
    assert len(recent_alerts) == 1
    print(f"✓ get_recent_alerts: {len(recent_alerts)} found")
    
    counts = get_alert_counts_by_severity()
    assert counts.get("CRITICAL") == 1
    print(f"✓ get_alert_counts_by_severity: {counts}")
    
    top_ips = get_top_attacking_ips()
    # Depending on query, might return list of dicts
    assert len(top_ips) == 1
    assert top_ips[0]['remote_ip'] == "10.0.0.99"
    print(f"✓ get_top_attacking_ips: {top_ips[0]['remote_ip']}")
    
    types = get_attack_type_distribution()
    assert types.get("sqli") == 1
    print(f"✓ get_attack_type_distribution: {types}")
    
    trend = get_risk_trend()
    assert len(trend) > 0
    print(f"✓ get_risk_trend: {len(trend)} buckets")
    
    details = get_ip_detail("10.0.0.99")
    assert details['total_events_24h'] == 1
    assert len(details['recent_alerts']) == 1
    assert len(details['triggered_flags']) == 1
    print(f"✓ get_ip_detail: verified complete view")
    
    # Cleanup
    close_db_connection()
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    print("\n✓ ALL STORAGE TESTS PASSED")


if __name__ == "__main__":
    try:
        test_persistence_and_alerts()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n✗ FAILED: {e}")
        raise
