# Context-Aware Web Attack Detection Framework

## Overview
A SOC/WAF-inspired web attack detection system that analyzes Nginx logs using hybrid detection (rules + behavior + ML).

## Module 1: Secure Nginx Log Ingestion ✓

### Architecture
- **Secure log parsing**: OWASP-compliant file handling
- **Input validation**: Pydantic models with strict type checking
- **FastAPI integration**: RESTful API for log ingestion
- **Comprehensive testing**: Unit tests covering security scenarios

### Project Structure
```
app/
├── core/
│   └── config.py          # Environment-based configuration
├── models/
│   └── log_event.py       # Pydantic models for log validation
├── services/
│   └── ingestor.py        # Secure log reading and parsing
└── main.py                # FastAPI application

logs/
└── access.log             # Sample Nginx JSON logs

tests/
└── test_ingestor.py       # Unit tests
```

### Security Features Implemented
1. **No code execution**: Safe JSON parsing only (no eval/exec)
2. **Input validation**: All fields validated via Pydantic
3. **Sanitization**: Null bytes and control characters removed
4. **Read-only access**: Files opened in read mode only
5. **Error handling**: Graceful failure without crashes
6. **IP validation**: IPv4/IPv6 format checking
7. **HTTP method validation**: Enum-based restriction

### Setup

1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Configure environment**:
```bash
copy .env.example .env
# Edit .env if needed (default log path: logs/access.log)
```

3. **Run the application**:
```bash
uvicorn app.main:app --reload
```

4. **Run tests**:
```bash
pytest -v
```

### API Endpoints

#### `GET /`
Health check endpoint.

**Response**:
```json
{
  "service": "Context-Aware Web Attack Detection Framework",
  "module": "Log Ingestion",
  "status": "operational",
  "version": "0.1.0"
}
```

#### `GET /api/v1/logs/ingest?limit=100`
Ingest and parse logs from the configured log file.

**Parameters**:
- `limit` (optional): Maximum number of log entries (1-10000, default: 100)

**Response**:
```json
{
  "success": true,
  "count": 10,
  "events": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "remote_ip": "192.168.1.100",
      "method": "GET",
      "url": "/api/users",
      "status": 200,
      "user_agent": "Mozilla/5.0...",
      "referer": "https://example.com",
      "body_bytes_sent": 1024,
      "request_time": 0.123
    }
  ]
}
```

#### `GET /api/v1/logs/stats`
Get statistics about the log file.

**Response**:
```json
{
  "success": true,
  "log_file": "logs/access.log",
  "total_events": 10,
  "valid_events": 10,
  "parse_errors": 0
}
```

### Nginx Configuration

To generate logs in the expected JSON format, configure Nginx with:

```nginx
log_format json_combined escape=json
'{'
  '"timestamp":"$time_iso8601",'
  '"remote_ip":"$remote_addr",'
  '"method":"$request_method",'
  '"url":"$request_uri",'
  '"status":$status,'
  '"user_agent":"$http_user_agent",'
  '"referer":"$http_referer",'
  '"body_bytes_sent":$body_bytes_sent,'
  '"request_time":$request_time'
'}';

access_log /var/log/nginx/access.log json_combined;
```

### Testing

Run all tests:
```bash
pytest -v tests/
```

Run with coverage:
```bash
pytest --cov=app --cov-report=html tests/
```

### Next Modules
- [ ] Module 2: Rule-Based Detection Engine
- [ ] Module 3: Behavioral Analysis Engine
- [ ] Module 4: ML Integration Layer
- [ ] Module 5: Risk Scoring System
- [ ] Module 6: Storage Layer
- [ ] Module 7: Alert Management
- [ ] Module 8: React Dashboard

### Development Notes

**Current Status**: Module 1 Complete ✓
- Secure ingestion pipeline implemented
- All security requirements met
- Tests passing
- Sample data provided

**What's Working**:
- JSON log parsing
- Pydantic validation
- FastAPI endpoints
- Error handling
- Security controls

**Known Limitations** (POC):
- No real-time log tailing (reads entire file)
- SQLite not yet integrated (coming in Module 6)
- No attack detection logic (coming in Modules 2-5)
