"""
Security hardening tests for log ingestion service.
Tests CRLF injection prevention, model immutability, path allowlisting, and resource caps.
"""
import pytest
import json
import os
from pathlib import Path
from datetime import datetime
from app.services.ingestor import LogIngestor, LogIngestorError, MAX_LINE_BYTES, HARD_MAX_EVENTS
from app.models.log_event import LogEvent, HTTPMethod
from pydantic import ValidationError


@pytest.fixture
def temp_log_file(tmp_path):
    """Create a temporary log file for testing"""
    log_file = tmp_path / "logs" / "test_access.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    return log_file


@pytest.fixture
def valid_log_entry():
    """Sample valid log entry"""
    return {
        "timestamp": "2024-01-15T10:30:00Z",
        "remote_ip": "192.168.1.100",
        "method": "GET",
        "url": "/api/users",
        "status": 200,
        "user_agent": "Mozilla/5.0",
        "referer": "https://example.com",
        "body_bytes_sent": 1024,
        "request_time": 0.123
    }


class TestCRLFRejection:
    """Test that CRLF injection attempts are rejected"""
    
    def test_url_with_crlf_rejected(self, valid_log_entry):
        """Test that URL containing CR or LF is rejected"""
        # Test CR
        data = valid_log_entry.copy()
        data["url"] = "/api/users\rmalicious"
        with pytest.raises(ValidationError, match="CR or LF"):
            LogEvent(**data)
        
        # Test LF
        data["url"] = "/api/users\nmalicious"
        with pytest.raises(ValidationError, match="CR or LF"):
            LogEvent(**data)
        
        # Test CRLF
        data["url"] = "/api/users\r\nmalicious"
        with pytest.raises(ValidationError, match="CR or LF"):
            LogEvent(**data)
    
    def test_user_agent_with_crlf_rejected(self, valid_log_entry):
        """Test that User-Agent containing CR or LF is rejected"""
        data = valid_log_entry.copy()
        
        # Test CR
        data["user_agent"] = "Mozilla\rExploit"
        with pytest.raises(ValidationError, match="CR or LF"):
            LogEvent(**data)
        
        # Test LF
        data["user_agent"] = "Mozilla\nExploit"
        with pytest.raises(ValidationError, match="CR or LF"):
            LogEvent(**data)
        
        # Test CRLF
        data["user_agent"] = "Mozilla\r\nExploit"
        with pytest.raises(ValidationError, match="CR or LF"):
            LogEvent(**data)
    
    def test_referer_with_crlf_rejected(self, valid_log_entry):
        """Test that Referer containing CR or LF is rejected"""
        data = valid_log_entry.copy()
        
        # Test CRLF
        data["referer"] = "https://example.com\r\nmalicious"
        with pytest.raises(ValidationError, match="CR or LF"):
            LogEvent(**data)
    
    def test_null_byte_still_rejected(self, valid_log_entry):
        """Test that null bytes are still rejected"""
        data = valid_log_entry.copy()
        
        data["url"] = "/api/users\x00malicious"
        with pytest.raises(ValidationError, match="null byte"):
            LogEvent(**data)
        
        data = valid_log_entry.copy()
        data["user_agent"] = "Mozilla\x00Exploit"
        with pytest.raises(ValidationError, match="null byte"):
            LogEvent(**data)


class TestModelImmutability:
    """Test that LogEvent model is immutable after creation"""
    
    def test_cannot_modify_url_after_creation(self, valid_log_entry):
        """Test that URL field cannot be modified after model creation"""
        event = LogEvent(**valid_log_entry)
        
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            event.url = "/malicious/path"
    
    def test_cannot_modify_remote_ip_after_creation(self, valid_log_entry):
        """Test that remote_ip field cannot be modified"""
        event = LogEvent(**valid_log_entry)
        
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            event.remote_ip = "1.1.1.1"
    
    def test_cannot_modify_method_after_creation(self, valid_log_entry):
        """Test that method field cannot be modified"""
        event = LogEvent(**valid_log_entry)
        
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            event.method = "POST"
    
    def test_model_is_hashable(self, valid_log_entry):
        """Test that frozen models can be used in sets/dicts"""
        event1 = LogEvent(**valid_log_entry)
        event2 = LogEvent(**valid_log_entry)
        
        # Should be able to add to set (requires hashable)
        event_set = {event1, event2}
        assert len(event_set) >= 1  # May be 1 if hash collision


class TestPathAllowlisting:
    """Test that path allowlisting and symlink protection work"""
    
    def test_file_inside_allowed_root(self, temp_log_file):
        """Test that files inside allowed root are accepted"""
        temp_log_file.write_text("")
        allowed_root = temp_log_file.parent
        
        # Should succeed
        ingestor = LogIngestor(temp_log_file, allowed_root=allowed_root)
        assert ingestor.file_path.is_file()
    
    def test_file_outside_allowed_root_rejected(self, tmp_path):
        """Test that files outside allowed root are rejected"""
        # Create allowed root
        allowed_root = tmp_path / "logs"
        allowed_root.mkdir()
        
        # Create file outside allowed root
        outside_file = tmp_path / "outside" / "evil.log"
        outside_file.parent.mkdir()
        outside_file.write_text("")
        
        # Should fail
        with pytest.raises(LogIngestorError, match="outside allowed root"):
            LogIngestor(outside_file, allowed_root=allowed_root)
    
    def test_parent_traversal_rejected(self, tmp_path):
        """Test that ../ path traversal is blocked"""
        # Create allowed root with a file
        allowed_root = tmp_path / "logs"
        allowed_root.mkdir()
        
        # Create file outside
        outside_file = tmp_path / "secret.log"
        outside_file.write_text("")
        
        # Try to access via ../
        traversal_path = allowed_root / ".." / "secret.log"
        
        # Should fail (resolves to outside allowed root)
        with pytest.raises(LogIngestorError, match="outside allowed root|does not exist"):
            LogIngestor(traversal_path, allowed_root=allowed_root)
    
    @pytest.mark.skipif(os.name == 'nt', reason="Symlink test may require admin on Windows")
    def test_symlink_escape_rejected(self, tmp_path):
        """Test that symlinks pointing outside allowed root are rejected"""
        # Create allowed root
        allowed_root = tmp_path / "logs"
        allowed_root.mkdir()
        
        # Create file outside allowed root
        outside_file = tmp_path / "secret.log"
        outside_file.write_text("")
        
        # Create symlink inside allowed root pointing outside
        symlink = allowed_root / "link_to_secret.log"
        
        try:
            symlink.symlink_to(outside_file)
            
            # Should fail (symlink resolves to outside allowed root)
            with pytest.raises(LogIngestorError, match="outside allowed root"):
                LogIngestor(symlink, allowed_root=allowed_root)
        except OSError:
            pytest.skip("Symlink creation not supported on this system")


class TestResourceCaps:
    """Test that resource caps prevent abuse"""
    
    def test_oversized_line_skipped(self, temp_log_file, valid_log_entry):
        """Test that lines exceeding MAX_LINE_BYTES are skipped"""
        # Create a line that's too large
        large_url = "/api/" + "A" * MAX_LINE_BYTES
        large_entry = valid_log_entry.copy()
        large_entry["url"] = large_url
        
        # Write oversized line and a normal line
        lines = [
            json.dumps(large_entry),
            json.dumps(valid_log_entry)
        ]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        events = list(ingestor.read_logs())
        
        # Should only get the valid entry (oversized skipped)
        assert len(events) == 1
        assert events[0].url == "/api/users"
    
    def test_max_events_cap_enforced(self, temp_log_file, valid_log_entry):
        """Test that max_events parameter caps the number of events returned"""
        # Write 50 valid entries
        lines = [json.dumps(valid_log_entry) for _ in range(50)]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        
        # Request only 10
        events = list(ingestor.read_logs(max_events=10))
        assert len(events) == 10
        
        # Request 25
        events = list(ingestor.read_logs(max_events=25))
        assert len(events) == 25
    
    def test_hard_max_events_enforced(self, temp_log_file, valid_log_entry):
        """Test that HARD_MAX_EVENTS is the absolute limit"""
        # Write 500 valid entries
        lines = [json.dumps(valid_log_entry) for _ in range(500)]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        
        # Request 500 (should be capped at HARD_MAX_EVENTS=200)
        events = list(ingestor.read_logs(max_events=500))
        assert len(events) == HARD_MAX_EVENTS
    
    def test_parse_log_line_rejects_oversized(self, tmp_path):
        """Test that parse_log_line rejects oversized lines"""
        temp_file = tmp_path / "logs" / "test.log"
        temp_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file.write_text("")
        
        ingestor = LogIngestor(temp_file, allowed_root=temp_file.parent)
        
        # Create oversized line
        large_line = "A" * (MAX_LINE_BYTES + 1)
        result = ingestor.parse_log_line(large_line, 1)
        
        assert result is None


class TestEndToEndSecurity:
    """End-to-end security validation"""
    
    def test_realistic_attack_payloads_rejected(self, temp_log_file):
        """Test that realistic attack payloads are properly rejected"""
        attack_payloads = [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "remote_ip": "192.168.1.1",
                "method": "GET",
                "url": "/api?param=value\r\nSet-Cookie: admin=true",  # CRLF injection
                "status": 200,
                "user_agent": "Mozilla/5.0",
                "referer": None,
                "body_bytes_sent": 0,
                "request_time": 0.1
            },
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "remote_ip": "192.168.1.1",
                "method": "GET",
                "url": "/api/users\x00DROP TABLE users",  # Null byte injection
                "status": 200,
                "user_agent": "Mozilla/5.0",
                "referer": None,
                "body_bytes_sent": 0,
                "request_time": 0.1
            }
        ]
        
        lines = [json.dumps(p) for p in attack_payloads]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        events = list(ingestor.read_logs())
        
        # Both attack payloads should be rejected during validation
        assert len(events) == 0
    
    def test_mixed_valid_and_malicious(self, temp_log_file, valid_log_entry):
        """Test that valid entries are processed while malicious ones are rejected"""
        entries = [
            valid_log_entry,  # Valid
            {**valid_log_entry, "url": "/bad\r\ninjection"},  # CRLF attack
            valid_log_entry,  # Valid
            {**valid_log_entry, "user_agent": "Evil\x00Null"},  # Null byte
            valid_log_entry,  # Valid
        ]
        
        lines = [json.dumps(e) for e in entries]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        events = list(ingestor.read_logs())
        
        # Should get 3 valid events
        assert len(events) == 3
        for event in events:
            assert event.url == "/api/users"
