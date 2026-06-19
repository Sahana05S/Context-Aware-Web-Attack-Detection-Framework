"""
Smoke tests for API endpoints.
Verifies that all Module 8 endpoints are reachable and return valid JSON structures.
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from app.api.main import app
from app.core.config import settings
from app.models import LogEvent
from app.storage import get_storage_service, get_db_connection, close_db_connection
from datetime import datetime

# Setup test DB
TEST_DB_PATH = "./data/test_api_smoke.db"
settings.DATABASE_PATH = TEST_DB_PATH

from app.api.deps import get_current_user
import pytest

app.dependency_overrides[get_current_user] = lambda: "testuser"
client = TestClient(app)

@pytest.fixture(autouse=True, scope="module")
def setup_api_test_db():
    setup_data()
    yield
    close_db_connection()
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except:
            pass

def setup_data():
    """Seed DB with some data for API to read"""
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except:
            pass
            
    close_db_connection()
    service = get_storage_service()
    
    # Create event
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="1.2.3.4",
        method="GET",
        url="/api/test",
        status=200,
        user_agent="Mozilla",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    # Store with some risk to generate alerts/stats
    event_id = service.store_detection_result(
        event=event,
        matches=[{"rule_id": "r1", "severity": "HIGH", "confidence": 1.0, "attack_type": "test"}],
        behavior_matches=[{"flag_id": "b1", "severity": "MEDIUM", "confidence": 0.8, "remote_ip": "1.2.3.4"}],
        ml_output={"ml_score": 0.8, "model_used": 1},
        risk_result={"risk_score": 90, "severity": "CRITICAL", "reasons": ["Test"], "signals": {}, "correlation": {}},
        derived={"path": "/api/test", "normalized_ua": "mozilla"}
    )
    if event_id is None:
        raise RuntimeError("Failed to store detection result in setup_data")
    print(f"Server stored event {event_id}")
    
    # Verify alert exists in DB directly
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    if count == 0:
         raise RuntimeError("No alerts created in DB during setup_data")
    print(f"DB has {count} alerts")

def test_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["db_status"] == "ok"
    print("✓ /api/v1/health passed")

def test_alerts():
    response = client.get("/api/v1/alerts?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert "alerts" in data
    assert "total" in data
    alerts = data["alerts"]
    assert isinstance(alerts, list)
    assert len(alerts) >= 1
    assert alerts[0]["severity"] == "CRITICAL"
    print("✓ /api/v1/alerts passed")

def test_stats_overview():
    response = client.get("/api/v1/stats/overview")
    assert response.status_code == 200
    data = response.json()
    assert "alert_counts" in data
    assert "top_ips" in data
    assert "attack_types" in data
    assert "risk_trend" in data
    assert data["alert_counts"].get("CRITICAL", 0) >= 1
    print("✓ /api/v1/stats/overview passed")

def test_ip_detail():
    response = client.get("/api/v1/ips/1.2.3.4")
    assert response.status_code == 200
    data = response.json()
    assert data["remote_ip"] == "1.2.3.4"
    assert data["total_events_24h"] >= 1
    print("✓ /api/v1/ips/{ip} passed")

def run_tests():
    print("Starting API Smoke Tests...")
    try:
        setup_data()
        test_health()
        test_alerts()
        test_stats_overview()
        test_ip_detail()
        print("\n✓ ALL API SMOKE TESTS PASSED")
    except Exception as e:
        print(f"\n✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
    finally:
        close_db_connection()
        if os.path.exists(TEST_DB_PATH):
            try:
                os.remove(TEST_DB_PATH)
            except:
                pass

if __name__ == "__main__":
    run_tests()
