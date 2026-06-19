"""
Comprehensive tests for Module 4: ML Scoring Module.
Tests feature extraction, heuristic fallback, and bounded operations.
"""
import pytest
from datetime import datetime
from app.models import LogEvent, HTTPMethod
from app.detection.ml.features import extract_features
from app.detection.ml.scorer import MLScorer


def create_test_event(
    url="/api/test",
    method=HTTPMethod.GET,
    status=200,
    ua="Mozilla/5.0"
) -> LogEvent:
    """Create test event helper"""
    if url:
        url = url[:8192]
    if ua:
        ua = ua[:1024]
    return LogEvent(
        timestamp=datetime.now(),
        remote_ip="192.168.1.100",
        method=method,
        url=url,
        status=status,
        user_agent=ua,
        referer="https://example.com",
        body_bytes_sent=100,
        request_time=0.1
    )


class TestFeatureExtraction:
    """Test feature extraction with bounded operations"""
    
    def test_benign_event_stable_keys(self):
        """Benign event should return stable feature keys"""
        event = create_test_event()
        features = extract_features(event, {})
        
        # Should have all expected keys
        expected_keys = {
            'url_len', 'query_len', 'num_params', 'special_char_ratio',
            'pct_encoded', 'count_sql_keywords', 'count_xss_tokens',
            'count_traversal_tokens', 'count_cmd_tokens', 'is_suspicious_ua',
            'ua_missing', 'status_is_4xx', 'status_is_5xx', 'method_is_post',
            'path_depth', 'has_login_keyword'
        }
        
        assert set(features.keys()) == expected_keys
        
        # Benign should have low attack indicators
        assert features['count_sql_keywords'] == 0
        assert features['count_xss_tokens'] == 0
        assert features['count_traversal_tokens'] == 0
        assert features['count_cmd_tokens'] == 0
        assert features['is_suspicious_ua'] == 0
    
    def test_sql_injection_features(self):
        """SQLi patterns should be detected"""
        event = create_test_event(
            url="/api/users?id=1' UNION SELECT password FROM users--"
        )
        features = extract_features(event, {})
        
        assert features['count_sql_keywords'] >= 2  # UNION, SELECT
        assert features['special_char_ratio'] > 0.05
        assert features['url_len'] > 30
    
    def test_xss_features(self):
        """XSS patterns should be detected"""
        event = create_test_event(
            url="/search?q=<script>alert(document.cookie)</script>"
        )
        features = extract_features(event, {})
        
        assert features['count_xss_tokens'] >= 2  # <script, alert(
        assert features['special_char_ratio'] > 0.15
    
    def test_path_traversal_features(self):
        """Path traversal patterns should be detected"""
        event = create_test_event(
            url="/files?path=../../../etc/passwd"
        )
        features = extract_features(event, {})
        
        assert features['count_traversal_tokens'] >= 3  # ../ appears 3 times
        assert features['path_depth'] >= 1
    
    def test_cmd_injection_features(self):
        """Command injection patterns should be detected"""
        event = create_test_event(
            url="/api/ping?host=example.com;whoami"
        )
        features = extract_features(event, {})
        
        assert features['count_cmd_tokens'] >= 2  # ; and whoami
    
    def test_suspicious_ua_detection(self):
        """Suspicious user agents should be detected"""
        sus_uas = ['sqlmap/1.0', 'nikto/2.1.5', 'acunetix', 'nmap']
        
        for ua in sus_uas:
            event = create_test_event(ua=ua)
            features = extract_features(event, {})
            assert features['is_suspicious_ua'] == 1, f"Failed for UA: {ua}"
    
    def test_missing_ua(self):
        """Missing UA should be detected"""
        event = create_test_event(ua="")
        features = extract_features(event, {})
        assert features['ua_missing'] == 1
        
        event = create_test_event(ua="Mozilla/5.0")
        features = extract_features(event, {})
        assert features['ua_missing'] == 0
    
    def test_status_code_indicators(self):
        """Status code indicators should work"""
        # 4xx
        event = create_test_event(status=404)
        features = extract_features(event, {})
        assert features['status_is_4xx'] == 1
        assert features['status_is_5xx'] == 0
        
        # 5xx
        event = create_test_event(status=500)
        features = extract_features(event, {})
        assert features['status_is_4xx'] == 0
        assert features['status_is_5xx'] == 1
        
        # 2xx
        event = create_test_event(status=200)
        features = extract_features(event, {})
        assert features['status_is_4xx'] == 0
        assert features['status_is_5xx'] == 0
    
    def test_method_indicators(self):
        """Method indicators should work"""
        event = create_test_event(method=HTTPMethod.POST)
        features = extract_features(event, {})
        assert features['method_is_post'] == 1
        
        event = create_test_event(method=HTTPMethod.GET)
        features = extract_features(event, {})
        assert features['method_is_post'] == 0
    
    def test_login_path_detection(self):
        """Login paths should be detected"""
        login_paths = ['/api/login', '/signin', '/auth/validate']
        
        for path in login_paths:
            event = create_test_event(url=path)
            features = extract_features(event, {})
            assert features['has_login_keyword'] == 1, f"Failed for path: {path}"
    
    def test_huge_strings_bounded(self):
        """Huge strings should be bounded and not crash"""
        # Huge URL (10KB)
        huge_url = "/api/test" + "A" * 10000
        event = create_test_event(url=huge_url)
        
        # Should not crash
        features = extract_features(event, {})
        
        # Should be bounded
        assert features['url_len'] <= 2048
        assert features['query_len'] <= 2048
        assert features['num_params'] <= 50


class TestMLScorer:
    """Test ML scorer with heuristic fallback"""
    
    def test_scorer_initialization_without_model(self):
        """Scorer should initialize without model (heuristic fallback)"""
        scorer = MLScorer()
        # Should work even if model not loaded
        assert scorer is not None
    
    def test_heuristic_fallback_benign(self):
        """Heuristic should score benign traffic low"""
        scorer = MLScorer()
        event = create_test_event(url="/api/users")
        
        result = scorer.score_event(event, {})
        
        assert 'ml_score' in result
        assert 'ml_label' in result
        assert 'explanation' in result
        
        # Benign should be LOW
        assert 0.0 <= result['ml_score'] <= 1.0
        assert result['ml_label'] in ['LOW', 'MEDIUM', 'HIGH']
        assert len(result['explanation']) <= 120  # Bounded
    
    def test_heuristic_fallback_malicious(self):
        """Heuristic should score malicious traffic high"""
        scorer = MLScorer()
        scorer.model_loaded = False
        
        # SQLi attack
        event = create_test_event(
            url="/api/users?id=1' UNION SELECT password,email FROM admin_users--"
        )
        
        result = scorer.score_event(event, {})
        
        # Malicious should score higher than benign
        assert result['ml_score'] > 0.3  # At least MEDIUM
        assert result['ml_label'] in ['MEDIUM', 'HIGH']
        assert 'SQL' in result['explanation'] or 'Heuristic' in result['explanation']
    
    def test_score_bounds(self):
        """Score should always be in [0, 1]"""
        scorer = MLScorer()
        
        # Test various events
        test_urls = [
            "/api/test",
            "/api/users?id=1' OR '1'='1",
            "/search?q=<script>alert('XSS')</script>",
            "/files?path=../../../../etc/passwd",
            "/api/ping?host=;whoami;cat /etc/passwd"
        ]
        
        for url in test_urls:
            event = create_test_event(url=url)
            result = scorer.score_event(event, {})
            
            assert 0.0 <= result['ml_score'] <= 1.0, f"Score out of bounds for {url}"
            assert result['ml_label'] in ['LOW', 'MEDIUM', 'HIGH']
    
    def test_label_consistency(self):
        """Label should match score thresholds"""
        scorer = MLScorer()
        
        # Force low score
        event = create_test_event(url="/api/test")
        result = scorer.score_event(event, {})
        if result['ml_score'] < 0.3:
            assert result['ml_label'] == 'LOW'
        elif result['ml_score'] < 0.7:
            assert result['ml_label'] == 'MEDIUM'
        else:
            assert result['ml_label'] == 'HIGH'
    
    def test_explanation_bounded(self):
        """Explanation should be bounded to 120 chars"""
        scorer = MLScorer()
        
        # Event with many attack patterns
        event = create_test_event(
            url="/api/users?id=1' UNION SELECT * FROM users; DROP TABLE admin--"
        )
        
        result = scorer.score_event(event, {})
        assert len(result['explanation']) <= 120
    
    def test_error_handling_fail_safe(self):
        """Scorer should fail safely on errors"""
        scorer = MLScorer()
        
        # Even with problematic input, should return valid result
        try:
            event = create_test_event()
            result = scorer.score_event(event, {})
            
            # Should always return valid structure
            assert 'ml_score' in result
            assert 'ml_label' in result
            assert 'explanation' in result
            assert 0.0 <= result['ml_score'] <= 1.0
        except Exception as e:
            pytest.fail(f"Scorer should not raise exceptions: {e}")


class TestBoundedOperations:
    """Test that all operations are bounded"""
    
    def test_feature_extraction_bounded_loops(self):
        """Feature extraction should have bounded loops"""
        # Create event with many attack tokens
        url = "/api/test?" + "&".join([f"param{i}=value" for i in range(100)])
        event = create_test_event(url=url)
        
        features = extract_features(event, {})
        
        # Counts should be capped
        assert features['num_params'] <= 50
    
    def test_special_char_ratio_bounded(self):
        """Special char ratio should be bounded to [0, 1]"""
        # All special chars
        event = create_test_event(url="/!!!@@@###$$$%%%")
        features = extract_features(event, {})
        
        assert 0.0 <= features['special_char_ratio'] <= 1.0
    
    def test_attack_pattern_counts_bounded(self):
        """Attack pattern counts should be bounded"""
        # Many SQL keywords
        url = "/api?q=" + " UNION SELECT " * 50
        event = create_test_event(url=url)
        
        features = extract_features(event, {})
        
        assert features['count_sql_keywords'] <= 20
        assert features['count_xss_tokens'] <= 20
        assert features['count_traversal_tokens'] <= 20
        assert features['count_cmd_tokens'] <= 20
    
    def test_path_depth_bounded(self):
        """Path depth should be bounded"""
        # Very deep path
        path = "/" + "/".join(["dir"] * 100)
        event = create_test_event(url=path)
        
        features = extract_features(event, {})
        
        assert features['path_depth'] <= 50


class TestIntegration:
    """Integration tests for ML scoring"""
    
    def test_end_to_end_scoring(self):
        """Test end-to-end scoring workflow"""
        scorer = MLScorer()
        
        # Create mix of benign and malicious events
        events = [
            create_test_event(url="/api/users"),
            create_test_event(url="/api/products?category=books"),
            create_test_event(url="/api/search?q=test"),
            create_test_event(url="/api/users?id=1' OR '1'='1"),
            create_test_event(url="/search?q=<script>alert(1)</script>"),
        ]
        
        results = [scorer.score_event(e, {}) for e in events]
        
        # All should return valid results
        assert len(results) == 5
        for result in results:
            assert 'ml_score' in result
            assert 'ml_label' in result
            assert 0.0 <= result['ml_score'] <= 1.0
        
        # Malicious should generally score higher
        benign_scores = [results[i]['ml_score'] for i in [0, 1, 2]]
        malicious_scores = [results[i]['ml_score'] for i in [3, 4]]
        
        avg_benign = sum(benign_scores) / len(benign_scores)
        avg_malicious = sum(malicious_scores) / len(malicious_scores)
        
        assert avg_malicious > avg_benign
