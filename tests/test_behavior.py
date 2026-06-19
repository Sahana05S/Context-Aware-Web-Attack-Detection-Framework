"""
Comprehensive tests for Module 3: Behavioral Analysis Engine.
Tests all 6 behavioral flags with positive and negative cases.
"""
import pytest
from datetime import datetime, timedelta
from app.models import LogEvent, HTTPMethod
from app.detection.behavior.models import BehaviorMatch, BehaviorSeverity
from app.detection.behavior.state import IPActivityStore
from app.detection.behavior.engine import (
    check_ip_burst_10s,
    check_ip_burst_60s,
    check_endpoint_scan_60s,
    check_high_404_rate_60s,
    check_login_bruteforce_5m,
    check_automation_or_missing_ua,
    check_ip_behavior,
    run_behavior_detection
)


@pytest.fixture
def activity_store():
    """Create fresh activity store for each test"""
    return IPActivityStore(max_events_per_ip=500, eviction_minutes=30)


@pytest.fixture
def base_timestamp():
    """Base timestamp for tests"""
    return datetime(2024, 1, 15, 12, 0, 0)


def create_event_data(timestamp, path="/api/test", status=200, method="GET", ua="Mozilla/5.0"):
    """Helper to create event data dict"""
    return {
        "timestamp": timestamp,
        "path": path,
        "status": status,
        "method": method,
        "normalized_ua": ua.lower()
    }


class TestIPBurst10s:
    """Test 10-second burst detection"""
    
    def test_positive_burst(self, base_timestamp):
        """Should detect burst of 25 requests in 10s"""
        events = [
            create_event_data(base_timestamp + timedelta(seconds=i))
            for i in range(25)
        ]
        
        match = check_ip_burst_10s("192.168.1.100", events, threshold=20)
        
        assert match is not None
        assert match.flag_id == "ip_burst_10s"
        assert match.severity in [BehaviorSeverity.MEDIUM, BehaviorSeverity.HIGH]
        assert match.confidence >= 0.70
        assert "25 reqs in 10s" in match.evidence
        assert match.window_seconds == 10
    
    def test_negative_no_burst(self, base_timestamp):
        """Should not trigger on normal rate"""
        events = [
            create_event_data(base_timestamp + timedelta(seconds=i))
            for i in range(15)
        ]
        
        match = check_ip_burst_10s("192.168.1.100", events, threshold=20)
        
        assert match is None


class TestIPBurst60s:
    """Test 60-second burst detection"""
    
    def test_positive_burst(self, base_timestamp):
        """Should detect burst of 120 requests in 60s"""
        events = [
            create_event_data(base_timestamp + timedelta(seconds=i % 60))
            for i in range(120)
        ]
        
        match = check_ip_burst_60s("192.168.1.100", events, threshold=100)
        
        assert match is not None
        assert match.flag_id == "ip_burst_60s"
        assert match.severity == BehaviorSeverity.MEDIUM
    
    def test_negative_no_burst(self, base_timestamp):
        """Should not trigger on normal rate"""
        events = [
            create_event_data(base_timestamp + timedelta(seconds=i))
            for i in range(80)
        ]
        
        match = check_ip_burst_60s("192.168.1.100", events, threshold=100)
        
        assert match is None


class TestEndpointScan60s:
    """Test endpoint scanning detection"""
    
    def test_positive_scan(self, base_timestamp):
        """Should detect 40 unique paths in 60s"""
        events = [
            create_event_data(base_timestamp, path=f"/api/endpoint{i}")
            for i in range(40)
        ]
        
        match = check_endpoint_scan_60s("192.168.1.100", events, threshold=30)
        
        assert match is not None
        assert match.flag_id == "endpoint_scan_60s"
        assert "40 unique paths" in match.evidence
        assert match.severity in [BehaviorSeverity.MEDIUM, BehaviorSeverity.HIGH]
    
    def test_negative_few_paths(self, base_timestamp):
        """Should not trigger on few unique paths"""
        events = [
            create_event_data(base_timestamp, path=f"/api/endpoint{i % 5}")
            for i in range(100)
        ]
        
        match = check_endpoint_scan_60s("192.168.1.100", events, threshold=30)
        
        assert match is None


class TestHigh404Rate60s:
    """Test high 404 rate detection"""
    
    def test_positive_high_404s(self, base_timestamp):
        """Should detect 25 404s in 60s"""
        events = [
            create_event_data(base_timestamp + timedelta(seconds=i), path=f"/missing{i}", status=404)
            for i in range(25)
        ]
        
        match = check_high_404_rate_60s("192.168.1.100", events, threshold=20)
        
        assert match is not None
        assert match.flag_id == "high_404_rate_60s"
        assert "25 404s" in match.evidence
        assert match.severity == BehaviorSeverity.MEDIUM
    
    def test_negative_low_404s(self, base_timestamp):
        """Should not trigger on low 404 rate"""
        events = [
            create_event_data(base_timestamp, status=200 if i % 10 != 0 else 404)
            for i in range(50)
        ]
        
        match = check_high_404_rate_60s("192.168.1.100", events, threshold=20)
        
        assert match is None


class TestLoginBruteforce5m:
    """Test login brute force detection"""
    
    def test_positive_bruteforce(self, base_timestamp):
        """Should detect 20 failed logins in 5min"""
        events = [
            create_event_data(
                base_timestamp + timedelta(seconds=i * 10),
                path="/api/login",
                status=401
            )
            for i in range(20)
        ]
        
        match = check_login_bruteforce_5m("192.168.1.100", events, threshold=15)
        
        assert match is not None
        assert match.flag_id == "login_bruteforce_5m"
        assert match.severity == BehaviorSeverity.HIGH
        assert "20 failed logins" in match.evidence
        assert "login" in match.evidence.lower()
        assert match.window_seconds == 300
    
    def test_positive_on_signin_path(self, base_timestamp):
        """Should detect on /signin paths"""
        events = [
            create_event_data(base_timestamp, path="/api/signin", status=403)
            for _ in range(18)
        ]
        
        match = check_login_bruteforce_5m("192.168.1.100", events, threshold=15)
        
        assert match is not None
    
    def test_negative_successful_logins(self, base_timestamp):
        """Should not trigger on successful logins"""
        events = [
            create_event_data(base_timestamp, path="/api/login", status=200)
            for _ in range(50)
        ]
        
        match = check_login_bruteforce_5m("192.168.1.100", events, threshold=15)
        
        assert match is None
    
    def test_negative_non_login_401s(self, base_timestamp):
        """Should not trigger on 401s for non-login paths"""
        events = [
            create_event_data(base_timestamp, path="/api/protected", status=401)
            for _ in range(25)
        ]
        
        match = check_login_bruteforce_5m("192.168.1.100", events, threshold=15)
        
        assert match is None


class TestAutomationOrMissingUA:
    """Test automation/tool detection"""
    
    def test_positive_missing_ua(self, base_timestamp):
        """Should detect missing UA"""
        events = [create_event_data(base_timestamp, ua="")]
        
        match = check_automation_or_missing_ua("192.168.1.100", events)
        
        assert match is not None
        assert match.flag_id == "automation_or_missing_ua"
        assert "Missing" in match.evidence
        assert match.severity == BehaviorSeverity.MEDIUM
    
    def test_positive_curl_ua(self, base_timestamp):
        """Should detect curl UA"""
        events = [create_event_data(base_timestamp, ua="curl/7.68.0")]
        
        match = check_automation_or_missing_ua("192.168.1.100", events)
        
        assert match is not None
        assert "curl" in match.evidence.lower()
    
    def test_positive_python_requests(self, base_timestamp):
        """Should detect python-requests"""
        events = [create_event_data(base_timestamp, ua="python-requests/2.28.0")]
        
        match = check_automation_or_missing_ua("192.168.1.100", events)
        
        assert match is not None
        assert "python-requests" in match.evidence.lower()
    
    def test_negative_normal_browser(self, base_timestamp):
        """Should not trigger on normal browser UA"""
        events = [create_event_data(base_timestamp, ua="Mozilla/5.0 (Windows NT 10.0) Chrome/91.0")]
        
        match = check_automation_or_missing_ua("192.168.1.100", events)
        
        assert match is None


class TestActivityStore:
    """Test state store functionality"""
    
    def test_add_event(self, activity_store, base_timestamp):
        """Should add event to store"""
        activity_store.add_event(
            "192.168.1.100",
            base_timestamp,
            "/api/test",
            200,
            "GET",
            "mozilla/5.0"
        )
        
        events = activity_store.get_events("192.168.1.100", 60, base_timestamp)
        assert len(events) == 1
        assert events[0]["path"] == "/api/test"
    
    def test_memory_cap_per_ip(self, base_timestamp):
        """Should enforce 500 event cap per IP"""
        store = IPActivityStore(max_events_per_ip=10, eviction_minutes=30)
        
        for i in range(15):
            store.add_event(
                "192.168.1.100",
                base_timestamp + timedelta(seconds=i),
                f"/path{i}",
                200,
                "GET",
                "mozilla"
            )
        
        events = store.get_events("192.168.1.100", 3600, base_timestamp + timedelta(seconds=20))
        # Should have only last 10 events
        assert len(events) == 10
        # Oldest event should be path5 (0-4 evicted)
        assert events[0]["path"] == "/path5"
    
    def test_time_window_filtering(self, activity_store, base_timestamp):
        """Should filter events by time window"""
        for i in range(100):
            activity_store.add_event(
                "192.168.1.100",
                base_timestamp + timedelta(seconds=i),
                "/api/test",
                200,
                "GET",
                "mozilla"
            )
        
        # Get events in last 30 seconds
        current_time = base_timestamp + timedelta(seconds=100)
        events = activity_store.get_events("192.168.1.100", 30, current_time)
        
        # Should have events from second 71-100
        assert 25 <= len(events) <= 35  # Approximately 30 events
    
    def test_ip_eviction(self, activity_store, base_timestamp):
        """Should evict inactive IPs"""
        # Add events for two IPs
        activity_store.add_event("192.168.1.100", base_timestamp, "/test", 200, "GET", "mozilla")
        activity_store.add_event("192.168.1.101", base_timestamp + timedelta(minutes=35), "/test", 200, "GET", "mozilla")
        
        assert activity_store.get_ip_count() == 2
        
        # Evict after 30 minutes
        evicted = activity_store.evict_inactive(base_timestamp + timedelta(minutes=40))
        
        # First IP should be evicted, second should remain
        assert evicted == 1
        assert activity_store.get_ip_count() == 1


class TestEvidenceSanitization:
    """Test evidence sanitization in BehaviorMatch"""
    
    def test_evidence_max_length(self):
        """Evidence should be truncated to 120 chars"""
        long_evidence = "A" * 200
        
        match = BehaviorMatch(
            flag_id="test",
            name="Test",
            severity=BehaviorSeverity.LOW,
            confidence=0.5,
            tags=["test"],
            evidence=long_evidence,
            fields_used=["test"],
            window_seconds=60
        )
        
        assert len(match.evidence) == 120
    
    def test_evidence_no_crlf(self):
        """Evidence should reject CRLF"""
        with pytest.raises(ValueError, match="CR or LF"):
            BehaviorMatch(
                flag_id="test",
                name="Test",
                severity=BehaviorSeverity.LOW,
                confidence=0.5,
                tags=[],
                evidence="test\r\nmalicious",
                fields_used=[],
                window_seconds=60
            )
    
    def test_evidence_no_null_byte(self):
        """Evidence should reject null bytes"""
        with pytest.raises(ValueError, match="null byte"):
            BehaviorMatch(
                flag_id="test",
                name="Test",
                severity=BehaviorSeverity.LOW,
                confidence=0.5,
                tags=[],
                evidence="test\x00malicious",
                fields_used=[],
                window_seconds=60
            )


class TestIntegration:
    """Integration tests for full behavioral detection"""
    
    def test_run_behavior_detection(self, activity_store):
        """Test end-to-end behavioral detection"""
        # Use current time for realistic testing
        base_timestamp = datetime.now()
        
        # Create simulated attack events
        events = []
        
        # Create burst attack from IP1 (30 requests in 10s to trigger burst)
        for i in range(30):
            events.append(LogEvent(
                timestamp=base_timestamp + timedelta(seconds=i),
                remote_ip="192.168.1.100",
                method=HTTPMethod.GET,
                url=f"/api/test{i}",
                status=200,
                user_agent="Mozilla/5.0",
                referer="https://example.com",
                body_bytes_sent=100,
                request_time=0.1
            ))
        
        # Create brute force from IP2 (20 failed logins to trigger brute force)
        for i in range(20):
            events.append(LogEvent(
                timestamp=base_timestamp + timedelta(seconds=i * 10),
                remote_ip="192.168.1.101",
                method=HTTPMethod.POST,
                url="/api/login",
                status=401,
                user_agent="Mozilla/5.0",
                referer="https://example.com",
                body_bytes_sent=100,
                request_time=0.1
            ))
        
        # Run detection
        results = run_behavior_detection(events, activity_store)
        
        # Verify results structure
        assert "detections" in results
        assert "statistics" in results
        
        # Should have flagged at least one IP (burst or brute force)
        assert results["statistics"]["ips_flagged"] >= 1
        assert results["statistics"]["total_flags"] >= 1
        
        # Check detections
        detections = results["detections"]
        assert len(detections) >= 1
        
        # Verify each detection has required fields
        for detection in detections:
            assert "remote_ip" in detection
            assert "flags" in detection
            assert len(detection["flags"]) > 0
            
            # Verify each flag has required fields
            for flag in detection["flags"]:
                assert "flag_id" in flag
                assert "severity" in flag
                assert "confidence" in flag
                assert "evidence" in flag


class TestModule3Patches:
    """Tests for Module 3.1 industry realism patches"""
    
    def test_static_asset_filtering_endpoint_scan(self, base_timestamp, monkeypatch):
        """Static assets should be ignored in endpoint scan when configured"""
        from app.core import config
        
        # Enable static asset filtering
        monkeypatch.setattr(config.settings, "ignore_static_assets", True)
        
        # Create 40 requests: 30 static + 10 dynamic
        events = []
        for i in range(30):
            events.append(create_event_data(base_timestamp, path=f"/static/file{i}.css"))
        for i in range(10):
            events.append(create_event_data(base_timestamp, path=f"/api/endpoint{i}"))
        
        # Should NOT trigger (only 10 non-static unique paths)
        match = check_endpoint_scan_60s("192.168.1.100", events, threshold=30)
        assert match is None
        
        # Disable filtering
        monkeypatch.setattr(config.settings, "ignore_static_assets", False)
        
        # Should trigger now (40 total unique paths)
        match = check_endpoint_scan_60s("192.168.1.100", events, threshold=30)
        assert match is not None
    
    def test_static_asset_filtering_high_404(self, base_timestamp, monkeypatch):
        """Static asset 404s should be ignored when configured"""
        from app.core import config
        
        # Enable static asset filtering
        monkeypatch.setattr(config.settings, "ignore_static_assets", True)
        
        # Create 25 404s: 20 static + 5 dynamic
        events = []
        for i in range(20):
            events.append(create_event_data(base_timestamp, path=f"/missing{i}.png", status=404))
        for i in range(5):
            events.append(create_event_data(base_timestamp, path=f"/api/missing{i}", status=404))
        
        # Should NOT trigger (only 5 non-static 404s)
        match = check_high_404_rate_60s("192.168.1.100", events, threshold=20)
        assert match is None
        
        # Disable filtering
        monkeypatch.setattr(config.settings, "ignore_static_assets", False)
        
        # Should trigger now (25 total 404s)
        match = check_high_404_rate_60s("192.168.1.100", events, threshold=20)
        assert match is not None
    
    def test_302_redirect_in_auth_toggle(self, base_timestamp, monkeypatch):
        """302 redirects should be included in auth failures when configured"""
        from app.core import config
        
        # Create 18 302 redirects on login path
        events = [
            create_event_data(base_timestamp, path="/api/login", status=302)
            for _ in range(18)
        ]
        
        # With include_redirects_in_auth=False (default), should NOT trigger
        monkeypatch.setattr(config.settings, "include_redirects_in_auth", False)
        match = check_login_bruteforce_5m("192.168.1.100", events, threshold=15)
        assert match is None
        
        # With include_redirects_in_auth=True, should trigger
        monkeypatch.setattr(config.settings, "include_redirects_in_auth", True)
        match = check_login_bruteforce_5m("192.168.1.100", events, threshold=15)
        assert match is not None
        assert "18 failed logins" in match.evidence
    
    def test_baseline_mode_dynamic_thresholds(self, monkeypatch):
        """Baseline mode should calculate dynamic thresholds"""
        from app.core import config
        from app.detection.behavior.engine import calculate_dynamic_threshold
        from datetime import datetime, timedelta
        
        base_time = datetime.now()
        
        # Create 250 events over 5 minutes (baseline_min_events=200)
        events = [
            {
                "timestamp": base_time + timedelta(seconds=i),
                "path": f"/api/test{i % 10}",
                "status": 200
            }
            for i in range(250)
        ]
        
        # Calculate dynamic threshold for 10s window
        # 250 events / 300 seconds = 0.833 RPS
        # Dynamic = 0.833 * 10 * 3 = ~25
        # Static = 20
        # Should return max(20, 25) = 25
        dynamic_thresh = calculate_dynamic_threshold(events, static_threshold=20, window_seconds=10)
        assert dynamic_thresh >= 20
        assert dynamic_thresh <= 200  # Hard cap at 10x static
    
    def test_baseline_mode_hard_cap(self):
        """Baseline mode should enforce hard cap at 10x static threshold"""
        from app.detection.behavior.engine import calculate_dynamic_threshold
        from datetime import datetime, timedelta
        
        base_time = datetime.now()
        
        # Create massive event count (1000 events in 10 seconds = 100 RPS)
        events = [
            {
                "timestamp": base_time + timedelta(milliseconds=i * 10),
                "path": f"/api/test{i}",
                "status": 200
            }
            for i in range(1000)
        ]
        
        # Should be capped at 10x static threshold
        dynamic_thresh = calculate_dynamic_threshold(events, static_threshold=20, window_seconds=10)
        assert dynamic_thresh <= 200  # Hard cap= 20 * 10
    
    def test_baseline_mode_insufficient_events(self, monkeypatch):
        """Baseline mode should use static threshold with insufficient events"""
        from app.core import config
        from app.detection.behavior.engine import calculate_dynamic_threshold
        from datetime import datetime, timedelta
        
        # Set baseline_min_events to 200
        monkeypatch.setattr(config.settings, "baseline_min_events", 200)
        
        base_time = datetime.now()
        
        # Create only 50 events (below minimum)
        events = [
            {
                "timestamp": base_time + timedelta(seconds=i),
                "path": "/api/test",
                "status": 200
            }
            for i in range(50)
        ]
        
        # Should return static threshold
        dynamic_thresh = calculate_dynamic_threshold(events, static_threshold=20, window_seconds=10)
        assert dynamic_thresh == 20
