"""
Verification tests for Module 6: Risk Scoring Engine.
Tests risk assessment, signal correlation, and output contract.
"""
from datetime import datetime
from app.models import LogEvent, HTTPMethod
from app.detection.risk import RiskEngine, RiskResult, RiskSeverity


def test_risk_result_contract():
    """Verify RiskResult contract schema"""
    print("Testing RiskResult Contract...")
    
    # Create minimal valid result
    result = RiskResult(
        risk_score=50,
        severity=RiskSeverity.MEDIUM,
        confidence=0.7,
        reasons=["Test reason"],
        signals={"rule_component": 0.3},
        correlation={"remote_ip": "1.1.1.1"}
    )
    
    # Verify fields
    assert result.risk_score == 50
    assert result.severity == RiskSeverity.MEDIUM
    assert result.confidence == 0.7
    assert len(result.reasons) == 1
    
    print(f"✓ RiskResult schema valid")
    print(f"✓ Risk Score: {result.risk_score}, Severity: {result.severity.value}")
    print()


def test_rule_high_yields_high_risk():
    """Rule HIGH alone should yield HIGH/CRITICAL risk"""
    print("Testing Rule HIGH Scenario...")
    
    engine = RiskEngine()
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/api/test",
        status=200,
        user_agent="Mozilla",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    # HIGH severity rule match
    rule_matches = [{
        "rule_id": "sqli_union_select",
        "severity": "HIGH",
        "confidence": 0.95
    }]
    
    result = engine.score_event(
        event=event,
        rule_matches=rule_matches,
        behavior_matches=[],
        ml_output={"ml_score": 0.1, "ml_label": "LOW", "model_used": False},
        derived={"path": "/api/test"}
    )
    
    # Should be HIGH or CRITICAL
    assert result.severity in [RiskSeverity.HIGH, RiskSeverity.CRITICAL]
    assert result.risk_score >= 50
    assert "Rule:" in result.reasons[0]
    
    print(f"✓ Risk Score: {result.risk_score}, Severity: {result.severity.value}")
    print(f"✓ Top Reason: {result.reasons[0]}")
    print()


def test_behavior_ml_correlation():
    """Behavior HIGH + ML MEDIUM should yield HIGH risk"""
    print("Testing Behavior + ML Correlation...")
    
    engine = RiskEngine()
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/api/test",
        status=200,
        user_agent="Mozilla",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    # MEDIUM rule + HIGH behavior + MEDIUM ML
    rule_matches = [{
        "rule_id": "test_rule",
        "severity": "MEDIUM",
        "confidence": 0.7
    }]
    
    behavior_matches = [{
        "flag_id": "high_404_rate_60s",
        "severity": "HIGH",
        "confidence": 0.8
    }]
    
    ml_output = {
        "ml_score": 0.65,
        "ml_label": "MEDIUM",
        "model_used": False
    }
    
    result = engine.score_event(
        event=event,
        rule_matches=rule_matches,
        behavior_matches=behavior_matches,
        ml_output=ml_output,
        derived={"path": "/api/test"}
    )
    
    # Should be HIGH due to multiple signals
    assert result.risk_score >= 50
    assert result.severity in [RiskSeverity.HIGH, RiskSeverity.CRITICAL]
    assert result.confidence > 0.5  # Multiple signals boost confidence
    
    print(f"✓ Risk Score: {result.risk_score}, Severity: {result.severity.value}")
    print(f"✓ Confidence: {result.confidence}")
    print(f"✓ Reasons ({len(result.reasons)}): {result.reasons}")
    print()


def test_ml_alone_capped():
    """ML HIGH alone should yield at most MEDIUM (ML is secondary)"""
    print("Testing ML Alone (Capped)...")
    
    engine = RiskEngine()
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/api/test",
        status=200,
        user_agent="Mozilla",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    # Only ML HIGH, no rules/behavior
    ml_output = {
        "ml_score": 0.95,
        "ml_label": "HIGH",
        "model_used": True
    }
    
    result = engine.score_event(
        event=event,
        rule_matches=[],
        behavior_matches=[],
        ml_output=ml_output,
        derived={"path": "/api/test"}
    )
    
    # ML alone capped at 0.15, so max ~15% = LOW/MEDIUM
    assert result.risk_score <= 49  # At most MEDIUM
    assert result.severity in [RiskSeverity.LOW, RiskSeverity.MEDIUM]
    
    print(f"✓ Risk Score: {result.risk_score}, Severity: {result.severity.value}")
    print(f"✓ ML component capped as designed (secondary role)")
    print()


def test_reasons_sanitized():
    """Test that reasons are sanitized and bounded"""
    print("Testing Reason Sanitization...")
    
    engine = RiskEngine()
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/admin/login",
        status=200,
        user_agent="Mozilla",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    rule_matches = [{
        "rule_id": "test_rule",
        "severity": "MEDIUM",
        "confidence": 0.7
    }]
    
    result = engine.score_event(
        event=event,
        rule_matches=rule_matches,
        behavior_matches=[],
        ml_output={"ml_score": 0.3, "ml_label": "LOW", "model_used": False},
        derived={"path": "/admin/login", "query": ""}
    )
    
    # Check sanitization
    for reason in result.reasons:
        assert len(reason) <= 120, f"Reason too long: {len(reason)}"
        assert all(c.isprintable() or c == ' ' for c in reason), "Non-printable chars found"
        assert '\r' not in reason and '\n' not in reason, "CRLF found"
    
    # Should have max 5 reasons
    assert len(result.reasons) <= 5
    
    print(f"✓ All {len(result.reasons)} reasons sanitized and bounded")
    print(f"✓ Reasons: {result.reasons}")
    print()


def test_fail_safe():
    """Test that risk engine never crashes"""
    print("Testing Fail-Safe Behavior...")
    
    engine = RiskEngine()
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/test",
        status=None,  # None status
        user_agent=None,  # None UA
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    # Should not crash even with malformed data
    try:
        result = engine.score_event(
            event=event,
            rule_matches=[],
            behavior_matches=[],
            ml_output={},
            derived={}
        )
        
        assert isinstance(result, RiskResult)
        assert 0 <= result.risk_score <= 100
        assert 0.0 <= result.confidence <= 1.0
        
        print("✓ Handled edge cases gracefully")
        print(f"✓ Result: score={result.risk_score}, severity={result.severity.value}")
        print()
    except Exception as e:
        print(f"✗ FAILED: {e}")
        raise


if __name__ == "__main__":
    print("=" * 60)
    print("MODULE 6 VERIFICATION: Risk Scoring Engine")
    print("=" * 60)
    print()
    
    try:
        test_risk_result_contract()
        test_rule_high_yields_high_risk()
        test_behavior_ml_correlation()
        test_ml_alone_capped()
        test_reasons_sanitized()
        test_fail_safe()
        
        print("=" * 60)
        print("✓ ALL TESTS PASSED")
        print("Module 6 Risk Scoring Engine fully functional.")
        print("=" * 60)
    except Exception as e:
        print("=" * 60)
        print(f"✗ TEST FAILED: {e}")
        print("=" * 60)
        raise
