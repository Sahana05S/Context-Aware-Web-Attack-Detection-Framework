"""
Comprehensive tests for Module 2: Rule-Based Detection Engine.
Tests all 12 builtin rules with positive and negative cases.
"""
import pytest
from datetime import datetime
from app.models import LogEvent, HTTPMethod
from app.detection.rules.builtin import (
    SQLiUnionSelectRule, SQLiTautologyRule, SQLiTimeBasedRule,
    XSSScriptTagRawRule, XSSScriptTagEncodedRule, XSSEventHandlersRule,
    TraversalRawRule, TraversalEncodedRule, SensitiveFileProbeRule,
    CmdInjectionRule, LongQueryRule, SuspiciousUserAgentRule
)
from app.detection.rules.engine import derive_context, run_rules
from app.detection.rules.registry import get_registry


@pytest.fixture
def base_event():
    """Create a base clean event for testing"""
    return {
        "timestamp": datetime.now(),
        "remote_ip": "192.168.1.100",
        "method": HTTPMethod.GET,
        "url": "/api/test",
        "status": 200,
        "user_agent": "Mozilla/5.0",
        "referer": "https://example.com",
        "body_bytes_sent": 512,
        "request_time": 0.1
    }


class TestSQLiUnionSelectRule:
    """Test SQLi UNION SELECT detection"""
    
    def test_positive_union_select(self, base_event):
        """Should detect UNION SELECT pattern"""
        data = base_event.copy()
        data["url"] = "/api/users?id=1 UNION SELECT username,password FROM users"
        event = LogEvent(**data)
        
        rule = SQLiUnionSelectRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "sqli_union_select"
        assert match.severity.value == "HIGH"
        assert match.confidence >= 0.8
        assert len(match.evidence) <= 120
        assert '\r' not in match.evidence
        assert '\n' not in match.evidence
        assert '\x00' not in match.evidence
    
    def test_negative_no_union_select(self, base_event):
        """Should not detect normal query"""
        data = base_event.copy()
        data["url"] = "/api/users?id=1&name=test"
        event = LogEvent(**data)
        
        rule = SQLiUnionSelectRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestSQLiTautologyRule:
    """Test SQLi tautology detection"""
    
    def test_positive_or_1_equals_1(self, base_event):
        """Should detect ' OR 1=1 tautology"""
        data = base_event.copy(); data["url"] = "/login?username=admin' OR 1=1--&password=x"; event = LogEvent(**data)
        
        rule = SQLiTautologyRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "sqli_tautology"
        assert match.severity.value == "HIGH"
    
    def test_negative_normal_query(self, base_event):
        """Should not detect normal query"""
        data = base_event.copy(); data["url"] = "/api/products?category=electronics&price=100"; event = LogEvent(**data)
        
        rule = SQLiTautologyRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestSQLiTimeBasedRule:
    """Test time-based SQLi detection"""
    
    def test_positive_sleep_pattern(self, base_event):
        """Should detect SLEEP() function"""
        data = base_event.copy(); data["url"] = "/api/user?id=1 AND sleep(5)"; event = LogEvent(**data)
        
        rule = SQLiTimeBasedRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "sqli_time_based"
    
    def test_negative_no_time_functions(self, base_event):
        """Should not trigger on normal queries"""
        data = base_event.copy(); data["url"] = "/api/users?filter=active&sort=name"; event = LogEvent(**data)
        
        rule = SQLiTimeBasedRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestXSSScriptTagRawRule:
    """Test XSS script tag detection"""
    
    def test_positive_script_tag(self, base_event):
        """Should detect <script> tag"""
        data = base_event.copy(); data["url"] = "/search?q=<script>alert(1)</script>"; event = LogEvent(**data)
        
        rule = XSSScriptTagRawRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "xss_script_tag_raw"
        assert match.severity.value == "HIGH"
    
    def test_negative_no_script(self, base_event):
        """Should not trigger on normal text"""
        data = base_event.copy(); data["url"] = "/search?q=javascript tutorial"; event = LogEvent(**data)
        
        rule = XSSScriptTagRawRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestXSSScriptTagEncodedRule:
    """Test encoded XSS script tag detection"""
    
    def test_positive_encoded_script(self, base_event):
        """Should detect %3cscript (URL-encoded <script>)"""
        data = base_event.copy(); data["url"] = "/search?q=%3cscript%3ealert(1)%3c/script%3e"; event = LogEvent(**data)
        
        rule = XSSScriptTagEncodedRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "xss_script_tag_encoded"
    
    def test_negative_normal_encoded_url(self, base_event):
        """Should not trigger on normal encoded URL"""
        data = base_event.copy(); data["url"] = "/search?q=hello%20world"; event = LogEvent(**data)
        
        rule = XSSScriptTagEncodedRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestXSSEventHandlersRule:
    """Test XSS event handler detection"""
    
    def test_positive_onerror(self, base_event):
        """Should detect onerror= event handler"""
        data = base_event.copy(); data["url"] = "/page?data=<img src=x onerror=alert(1)>"; event = LogEvent(**data)
        
        rule = XSSEventHandlersRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "xss_event_handlers"
    
    def test_negative_no_handlers(self, base_event):
        """Should not trigger without event handlers"""
        data = base_event.copy(); data["url"] = "/page?title=error handling in javascript"; event = LogEvent(**data)
        
        rule = XSSEventHandlersRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestTraversalRawRule:
    """Test path traversal detection"""
    
    def test_positive_dot_dot_slash(self, base_event):
        """Should detect ../ pattern"""
        data = base_event.copy(); data["url"] = "/files?path=../../../etc/passwd"; event = LogEvent(**data)
        
        rule = TraversalRawRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "traversal_raw"
        assert match.severity.value == "HIGH"
    
    def test_negative_normal_path(self, base_event):
        """Should not trigger on normal paths"""
        data = base_event.copy(); data["url"] = "/api/v1/users/list"; event = LogEvent(**data)
        
        rule = TraversalRawRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestTraversalEncodedRule:
    """Test encoded path traversal detection"""
    
    def test_positive_encoded_traversal(self, base_event):
        """Should detect %2e%2e%2f (encoded ../)"""
        data = base_event.copy(); data["url"] = "/files?path=%2e%2e%2f%2e%2e%2fetc/passwd"; event = LogEvent(**data)
        
        rule = TraversalEncodedRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "traversal_encoded"
    
    def test_negative_normal_encoded_path(self, base_event):
        """Should not trigger on normal encoded paths"""
        data = base_event.copy(); data["url"] = "/api/files?name=my%20document.pdf"; event = LogEvent(**data)
        
        rule = TraversalEncodedRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestSensitiveFileProbeRule:
    """Test sensitive file probe detection"""
    
    def test_positive_env_file(self, base_event):
        """Should detect .env file access"""
        data = base_event.copy(); data["url"] = "/.env"; event = LogEvent(**data)
        
        rule = SensitiveFileProbeRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "sensitive_file_probe"
    
    def test_negative_normal_file(self, base_event):
        """Should not trigger on normal files"""
        data = base_event.copy(); data["url"] = "/static/css/style.css"; event = LogEvent(**data)
        
        rule = SensitiveFileProbeRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestCmdInjectionRule:
    """Test command injection detection"""
    
    def test_positive_semicolon_separator(self, base_event):
        """Should detect ; command separator"""
        data = base_event.copy(); data["url"] = "/api/ping?host=127.0.0.1;cat /etc/passwd"; event = LogEvent(**data)
        
        rule = CmdInjectionRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "cmd_injection_separators"
    
    def test_negative_normal_query(self, base_event):
        """Should not trigger on normal queries"""
        data = base_event.copy(); data["url"] = "/api/search?q=network commands"; event = LogEvent(**data)
        
        rule = CmdInjectionRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestLongQueryRule:
    """Test long query detection"""
    
    def test_positive_long_query(self, base_event):
        """Should detect suspiciously long query"""
        long_query = "param=" + "A" * 600
        data = base_event.copy()
        data["url"] = f"/api/test?{long_query}"
        event = LogEvent(**data)
        
        rule = LongQueryRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "long_query"
        assert match.severity.value == "LOW"
    
    def test_negative_normal_query(self, base_event):
        """Should not trigger on normal query length"""
        data = base_event.copy(); data["url"] = "/api/test?id=123&name=test"; event = LogEvent(**data)
        
        rule = LongQueryRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestSuspiciousUserAgentRule:
    """Test suspicious user agent detection"""
    
    def test_positive_sqlmap_ua(self, base_event):
        """Should detect SQLMap user agent"""
        data = base_event.copy(); data["user_agent"] = "sqlmap/1.0"; event = LogEvent(**data)
        
        rule = SuspiciousUserAgentRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is not None
        assert match.rule_id == "suspicious_user_agent"
    
    def test_negative_normal_ua(self, base_event):
        """Should not trigger on normal user agent"""
        data = base_event.copy(); data["user_agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"; event = LogEvent(**data)
        
        rule = SuspiciousUserAgentRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        assert match is None


class TestEvidenceSanitization:
    """Test that all evidence is properly sanitized"""
    
    def test_evidence_max_length(self, base_event):
        """Evidence should be truncated to 120 chars"""
        # Create very long URL
        long_attack = "A" * 500
        data = base_event.copy()
        data["url"] = f"/api/test?attack={long_attack}"
        event = LogEvent(**data)
        
        rule = LongQueryRule()
        derived = derive_context(event)
        match = rule.match(event, derived)
        
        if match:
            assert len(match.evidence) <= 120
    
    def test_evidence_no_crlf(self):
        """Evidence should never contain CRLF"""
        # This should be rejected at LogEvent level
        # But we test that even if it somehow gets through,
        # RuleMatch validation catches it
        from app.detection.rules.models import RuleMatch, Severity
        
        with pytest.raises(ValueError, match="CR or LF"):
            RuleMatch(
                rule_id="test",
                name="Test",
                severity=Severity.LOW,
                confidence=0.5,
                evidence="test\r\nmalicious",
                tags=[],
                fields_used=[]
            )
    
    def test_evidence_no_null_byte(self):
        """Evidence should never contain null bytes"""
        from app.detection.rules.models import RuleMatch, Severity
        
        with pytest.raises(ValueError, match="null byte"):
            RuleMatch(
                rule_id="test",
                name="Test",
                severity=Severity.LOW,
                confidence=0.5,
                evidence="test\x00malicious",
                tags=[],
                fields_used=[]
            )


class TestEngineEdgeCases:
    """Test detection engine with edge cases"""
    
    def test_unicode_handling(self, base_event):
        """Engine should handle unicode gracefully"""
        data = base_event.copy(); data["url"] = "/search?q=тест🎉"; event = LogEvent(**data)
        
        derived = derive_context(event)
        rules = [SQLiUnionSelectRule()]
        matches = run_rules(event, rules)
        
        # Should not crash
        assert isinstance(matches, list)
    
    def test_very_long_url(self, base_event):
        """Engine should cap processing of very long URLs"""
        long_url = "/test?" + "A" * 10000
        data = base_event.copy(); data["url"] = long_url[:8192  # URL is capped at model level
        ]; event = LogEvent(**data)
        
        derived = derive_context(event)
        
        # Should not crash and should have capped derived values
        assert "decoded_url" in derived
        assert len(derived["decoded_url"]) <= 4096  # MAX_DECODE_LEN


class TestRuleRegistry:
    """Test rule registry functionality"""
    
    def test_registry_has_12_rules(self):
        """Registry should have all 12 builtin rules"""
        registry = get_registry()
        all_rules = registry.get_all_rules()
        
        assert len(all_rules) == 12
    
    def test_all_rules_enabled_by_default(self):
        """All rules should be enabled by default"""
        registry = get_registry()
        enabled_rules = registry.get_enabled_rules()
        
        assert len(enabled_rules) == 12
    
    def test_can_disable_rule(self):
        """Should be able to disable a rule"""
        registry = get_registry()
        
        # Disable one rule
        registry.disable_rule("sqli_union_select")
        enabled = registry.get_enabled_rules()
        
        # Should have 11 enabled rules now
        assert len(enabled) == 11
        assert not any(r.rule_id == "sqli_union_select" for r in enabled)
        
        # Re-enable for other tests
        registry.enable_rule("sqli_union_select")
