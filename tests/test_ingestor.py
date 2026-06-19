"""
Unit tests for log ingestion service.
Tests secure parsing, validation, and error handling.
"""
import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from app.services.ingestor import LogIngestor, LogIngestorError
from app.models.log_event import LogEvent, HTTPMethod
from pydantic import ValidationError
from app.core.config import settings

# Override allowed log root to temp dir for test environment safety on Windows
settings.log_root_dir = Path(tempfile.gettempdir())


@pytest.fixture
def temp_log_file(tmp_path):
    """Create a temporary log file for testing"""
    log_file = tmp_path / "test_access.log"
    return log_file


@pytest.fixture
def valid_log_entries():
    """Sample valid log entries in JSON format"""
    return [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "remote_ip": "192.168.1.100",
            "method": "GET",
            "url": "/api/users",
            "status": 200,
            "user_agent": "Mozilla/5.0",
            "referer": "https://example.com",
            "body_bytes_sent": 1024,
            "request_time": 0.123
        },
        {
            "timestamp": "2024-01-15T10:31:00Z",
            "remote_ip": "10.0.0.5",
            "method": "POST",
            "url": "/api/login",
            "status": 401,
            "user_agent": "curl/7.68.0",
            "referer": None,
            "body_bytes_sent": 256,
            "request_time": 0.045
        }
    ]


class TestLogEventModel:
    """Test LogEvent Pydantic model validation"""
    
    def test_valid_log_event(self, valid_log_entries):
        """Test creating a valid log event"""
        event = LogEvent(**valid_log_entries[0])
        assert event.remote_ip == "192.168.1.100"
        assert event.method == HTTPMethod.GET
        assert event.status == 200
    
    def test_invalid_ip_address(self, valid_log_entries):
        """Test that invalid IP addresses are rejected"""
        data = valid_log_entries[0].copy()
        data["remote_ip"] = "999.999.999.999"
        
        with pytest.raises(ValidationError):
            LogEvent(**data)
    
    def test_invalid_http_method(self, valid_log_entries):
        """Test that invalid HTTP methods are rejected"""
        data = valid_log_entries[0].copy()
        data["method"] = "INVALID"
        
        with pytest.raises(ValidationError):
            LogEvent(**data)
    
    def test_status_code_validation(self, valid_log_entries):
        """Test HTTP status code range validation"""
        data = valid_log_entries[0].copy()
        
        # Valid status codes
        for status in [200, 404, 500]:
            data["status"] = status
            event = LogEvent(**data)
            assert event.status == status
        
        # Invalid status codes
        for status in [99, 600, 1000]:
            data["status"] = status
            with pytest.raises(ValidationError):
                LogEvent(**data)
    
    def test_url_sanitization(self, valid_log_entries):
        """Test URL sanitization (null byte removal)"""
        data = valid_log_entries[0].copy()
        data["url"] = "/api/users\x00malicious"
        
        with pytest.raises(ValidationError):
            LogEvent(**data)
    
    def test_header_sanitization(self, valid_log_entries):
        """Test header sanitization"""
        data = valid_log_entries[0].copy()
        data["user_agent"] = "Mozilla\x00Exploit"
        
        with pytest.raises(ValidationError):
            LogEvent(**data)
    
    def test_optional_fields(self, valid_log_entries):
        """Test that optional fields can be None"""
        data = valid_log_entries[0].copy()
        data["user_agent"] = None
        data["referer"] = None
        
        event = LogEvent(**data)
        assert event.user_agent is None
        assert event.referer is None


class TestLogIngestor:
    """Test LogIngestor service"""
    
    def test_ingestor_initialization_valid_file(self, temp_log_file):
        """Test ingestor initialization with valid file"""
        temp_log_file.write_text("")
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        # Path will be resolved to absolute
        assert ingestor.file_path.name == temp_log_file.name
    
    def test_ingestor_initialization_missing_file(self, tmp_path):
        """Test ingestor fails with missing file"""
        missing_file = tmp_path / "nonexistent.log"
        
        with pytest.raises(LogIngestorError, match="does not exist"):
            LogIngestor(missing_file)
    
    def test_ingestor_initialization_directory(self, tmp_path):
        """Test ingestor fails when given a directory"""
        with pytest.raises(LogIngestorError, match="not a file"):
            LogIngestor(tmp_path)
    
    def test_parse_valid_log_line(self, temp_log_file, valid_log_entries):
        """Test parsing a valid JSON log line"""
        temp_log_file.write_text("")
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        line = json.dumps(valid_log_entries[0])
        event = ingestor.parse_log_line(line, 1)
        
        assert event is not None
        assert event.remote_ip == "192.168.1.100"
        assert event.method == HTTPMethod.GET
    
    def test_parse_invalid_json(self, temp_log_file):
        """Test handling of invalid JSON"""
        temp_log_file.write_text("")
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        event = ingestor.parse_log_line("not valid json", 1)
        assert event is None  # Should return None, not crash
    
    def test_parse_missing_required_fields(self, temp_log_file):
        """Test handling of JSON with missing required fields"""
        temp_log_file.write_text("")
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        line = json.dumps({"timestamp": "2024-01-15T10:30:00Z"})
        event = ingestor.parse_log_line(line, 1)
        assert event is None  # Should return None due to validation failure
    
    def test_read_logs_multiple_entries(self, temp_log_file, valid_log_entries):
        """Test reading multiple log entries"""
        # Write multiple JSON lines
        lines = [json.dumps(entry) for entry in valid_log_entries]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        events = list(ingestor.read_logs())
        
        assert len(events) == 2
        assert events[0].remote_ip == "192.168.1.100"
        assert events[1].remote_ip == "10.0.0.5"
    
    def test_read_logs_with_empty_lines(self, temp_log_file, valid_log_entries):
        """Test that empty lines are skipped"""
        lines = [
            json.dumps(valid_log_entries[0]),
            "",
            "   ",
            json.dumps(valid_log_entries[1])
        ]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file)
        events = list(ingestor.read_logs())
        
        assert len(events) == 2
    
    def test_read_logs_with_malformed_entries(self, temp_log_file, valid_log_entries):
        """Test that malformed entries are skipped gracefully"""
        lines = [
            json.dumps(valid_log_entries[0]),
            "malformed json",
            json.dumps(valid_log_entries[1]),
            "{incomplete",
        ]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file)
        events = list(ingestor.read_logs())
        
        # Should successfully parse the 2 valid entries
        assert len(events) == 2
    
    def test_security_no_code_execution(self, temp_log_file):
        """Test that malicious payloads are not executed"""
        # Attempt to inject code via various fields
        malicious_entry = {
            "timestamp": "2024-01-15T10:30:00Z",
            "remote_ip": "192.168.1.1",
            "method": "GET",
            "url": "/api'; DROP TABLE users; --",
            "status": 200,
            "user_agent": "__import__('os').system('whoami')",
            "referer": "javascript:alert(1)",
            "body_bytes_sent": 0,
            "request_time": 0.1
        }
        
        temp_log_file.write_text(json.dumps(malicious_entry))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        events = list(ingestor.read_logs())
        
        # Event should be parsed safely without code execution
        assert len(events) == 1
        # Values should be stored as strings, not executed
        assert "DROP TABLE" in events[0].url
        assert "import" in events[0].user_agent


class TestEndToEndParsing:
    """End-to-end integration tests"""
    
    def test_realistic_nginx_logs(self, temp_log_file):
        """Test with realistic Nginx JSON log format"""
        realistic_logs = [
            {
                "timestamp": "2024-01-15T14:23:45Z",
                "remote_ip": "203.0.113.45",
                "method": "GET",
                "url": "/api/v1/products?category=electronics&page=2",
                "status": 200,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "referer": "https://shop.example.com/browse",
                "body_bytes_sent": 4096,
                "request_time": 0.234
            },
            {
                "timestamp": "2024-01-15T14:23:46Z",
                "remote_ip": "2001:db8::1",
                "method": "POST",
                "url": "/api/v1/orders",
                "status": 201,
                "user_agent": "MobileApp/2.1.0 (iOS 17.0)",
                "referer": None,
                "body_bytes_sent": 512,
                "request_time": 0.567
            }
        ]
        
        lines = [json.dumps(log) for log in realistic_logs]
        temp_log_file.write_text('\n'.join(lines))
        
        ingestor = LogIngestor(temp_log_file, allowed_root=temp_log_file.parent)
        events = list(ingestor.read_logs())
        
        assert len(events) == 2
        
        # Verify IPv4
        assert events[0].remote_ip == "203.0.113.45"
        
        # Verify IPv6
        assert events[1].remote_ip == "2001:db8::1"
        
        # Verify query parameters are preserved
        assert "category=electronics" in events[0].url
