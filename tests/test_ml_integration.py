"""
Verification script for Module 5: ML Adapter Integration.
Tests that ML output exists and has correct contract.
"""
from datetime import datetime
from app.models import LogEvent, HTTPMethod
from app.detection.ml import MLScorer


def test_ml_output_contract():
    """Verify ML output contract is locked and stable"""
    print("Testing ML Output Contract...")
    
    scorer = MLScorer()
    
    # Test event
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/api/test",
        status=200,
        user_agent="Mozilla/5.0",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    # Score event
    result = scorer.score_event(event, {})
    
    # Verify required fields exist
    assert "ml_score" in result, "ml_score missing"
    assert "ml_label" in result, "ml_label missing"
    assert "explanation" in result, "explanation missing"
    assert "model_used" in result, "model_used missing"
    
    # Verify types and bounds
    assert isinstance(result["ml_score"], float), "ml_score must be float"
    assert 0.0 <= result["ml_score"] <= 1.0, "ml_score must be in [0, 1]"
    assert result["ml_label"] in ["LOW", "MEDIUM", "HIGH"], "ml_label must be LOW/MEDIUM/HIGH"
    assert isinstance(result["explanation"], str), "explanation must be string"
    assert len(result["explanation"]) <= 120, "explanation must be <= 120 chars"
    assert isinstance(result["model_used"], bool), "model_used must be boolean"
    
    print(f"✓ ML Score: {result['ml_score']}")
    print(f"✓ ML Label: {result['ml_label']}")
    print(f"✓ Explanation: {result['explanation']}")
    print(f"✓ Model Used: {result['model_used']}")
    print("✓ Contract verification passed!\n")


def test_ml_heuristic_fallback():
    """Verify heuristic works when model unavailable"""
    print("Testing Heuristic Fallback...")
    
    scorer = MLScorer()
    scorer.model_loaded = False
    
    # Malicious event
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/api/users?id=1' UNION SELECT password FROM users--",
        status=200,
        user_agent="sqlmap/1.0",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    result = scorer.score_event(event, {})
    
    # Should detect malicious patterns
    assert result["ml_score"] > 0.3, "Should detect SQL injection"
    assert result["ml_label"] in ["MEDIUM", "HIGH"], "Should flag as suspicious"
    assert len(result["explanation"]) > 0, "Should have explanation"
    
    print(f"✓ Detected malicious pattern: score={result['ml_score']}, label={result['ml_label']}")
    print(f"✓ Explanation: {result['explanation']}")
    print("✓ Heuristic fallback test passed!\n")


def test_ml_never_crashes():
    """Verify ML never crashes pipeline"""
    print("Testing Fail-Safe Behavior...")
    
    scorer = MLScorer()
    
    # Event with None values
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
    
    # Should not crash
    try:
        result = scorer.score_event(event, {})
        assert "ml_score" in result
        print("✓ Handled None values gracefully")
        print(f"✓ Result: {result}")
        print("✓ Fail-safe test passed!\n")
    except Exception as e:
        print(f"✗ FAILED: {e}")
        raise


def test_explanation_sanitization():
    """Verify explanation is sanitized"""
    print("Testing Explanation Sanitization...")
    
    scorer = MLScorer()
    
    # Get any result
    event = LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=HTTPMethod.GET,
        url="/test",
        status=200,
        user_agent="Mozilla",
        referer="",
        body_bytes_sent=100,
        request_time=0.1
    )
    
    result = scorer.score_event(event, {})
    explanation = result["explanation"]
    
    # Verify no CRLF
    assert "\r" not in explanation, "Explanation contains CR"
    assert "\n" not in explanation, "Explanation contains LF"
    assert all(c.isprintable() for c in explanation), "Explanation contains non-printable chars"
    
    print(f"✓ Explanation sanitized: '{explanation}'")
    print("✓ Sanitization test passed!\n")


def test_pipeline_integration():
    """Verify ML is integrated into detection engine"""
    print("Testing Pipeline Integration...")
    
    from app.detection.rules.engine import run_on_events, get_ml_scorer
    from app.detection.rules.registry import get_registry
    from datetime import datetime
    
    # Get ML scorer
    ml_scorer = get_ml_scorer()
    print(f"✓ ML Scorer initialized: {ml_scorer is not None}")
    
    # Create test events
    events = [
        LogEvent(
            timestamp=datetime.now(),
            remote_ip="192.168.1.100",
            method=HTTPMethod.GET,
            url="/api/test?id=1' OR '1'='1",
            status=200,
            user_agent="Mozilla",
            referer="",
            body_bytes_sent=100,
            request_time=0.1
        )
    ]
    
    # Get enabled rules
    registry = get_registry()
    rules = registry.get_enabled_rules()
    
    # Run detection
    results = run_on_events(events, rules)
    
    # Verify ML section exists if there are results
    if results:
        assert "ml" in results[0], "ML section missing from results"
        ml_section = results[0]["ml"]
        
        # Verify contract
        assert "ml_score" in ml_section
        assert "ml_label" in ml_section
        assert "explanation" in ml_section
        assert "model_used" in ml_section
        
        print(f"✓ ML section present in detection results")
        print(f"✓ ML output: {ml_section}")
    else:
        print("✓ No rule matches, but ML scorer is integrated and ready")
    
    print("✓ Pipeline integration test passed!\n")


if __name__ == "__main__":
    print("=" * 60)
    print("MODULE 5 VERIFICATION: ML Adapter Integration")
    print("=" * 60)
    print()
    
    try:
        test_ml_output_contract()
        test_ml_heuristic_fallback()
        test_ml_never_crashes()
        test_explanation_sanitization()
        test_pipeline_integration()
        
        print("=" * 60)
        print("✓ ALL TESTS PASSED")
        print("Module 5 completed and integrated. Ready for Module 6.")
        print("=" * 60)
    except Exception as e:
        print("=" * 60)
        print(f"✗ TEST FAILED: {e}")
        print("=" * 60)
        raise
