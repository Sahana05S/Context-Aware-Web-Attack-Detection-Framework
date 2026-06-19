"""
Log format parsers for the ingest pipeline.
Supports: Nginx/Apache combined log format, and CSV with our schema.
"""
import re
import csv
import io
import logging
from datetime import datetime, timezone
from typing import Optional, Literal

from app.models import LogEvent, HTTPMethod

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Nginx / Apache combined log format:
#   ip - - [day/mon/year:h:m:s tz] "METHOD /path HTTP/x.x" status bytes "ref" "ua"
# ---------------------------------------------------------------------------
_NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+'           # remote IP
    r'\S+\s+\S+\s+'              # ident, auth (ignored)
    r'\[(?P<time>[^\]]+)\]\s+'   # timestamp
    r'"(?P<method>[A-Z]{1,10})\s+'  # HTTP method
    r'(?P<url>\S+)\s+'           # URL
    r'\S+"\s+'                   # HTTP version + closing quote
    r'(?P<status>\d{3})\s+'      # status code
    r'(?P<bytes>\d+|-)'          # body bytes
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'  # optional referer + UA
)

_NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# Valid HTTP methods for safe parsing
_VALID_METHODS = {m.value for m in HTTPMethod}


def detect_format(first_line: str) -> Literal["nginx", "csv", "unknown"]:
    """
    Auto-detect log format from the first line of a file.
    """
    stripped = first_line.strip()
    if not stripped:
        return "unknown"
    # CSV: starts with a header that contains 'timestamp' or 'remote_ip'
    if "timestamp" in stripped.lower() or "remote_ip" in stripped.lower():
        return "csv"
    # Nginx: first token looks like an IP, contains brackets
    if "[" in stripped and '"' in stripped:
        return "nginx"
    return "unknown"


def parse_nginx_line(line: str, line_no: int = 0) -> Optional[LogEvent]:
    """
    Parse a single Nginx/Apache combined access log line into a LogEvent.
    Returns None on parse failure (invalid lines are skipped gracefully).
    Handles lines wrapped in outer quotes (e.g. from CSV exports of logs).
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Strip outer wrapping quotes if present (e.g. acunetix/netsparker CSV exports)
    if line.startswith('"') and line.endswith('"'):
        line = line[1:-1]

    m = _NGINX_RE.match(line)
    if not m:
        logger.debug(f"Line {line_no}: no Nginx pattern match")
        return None

    try:
        method_str = m.group("method").upper()
        if method_str not in _VALID_METHODS:
            logger.debug(f"Line {line_no}: invalid HTTP method '{method_str}'")
            return None

        ts = datetime.strptime(m.group("time"), _NGINX_TIME_FMT)
        bytes_sent = m.group("bytes")
        body_bytes = int(bytes_sent) if bytes_sent and bytes_sent != "-" else 0

        return LogEvent(
            timestamp=ts,
            remote_ip=m.group("ip"),
            method=HTTPMethod(method_str),
            url=m.group("url"),
            status=int(m.group("status")),
            user_agent=m.group("ua") or None,
            referer=m.group("referer") or None,
            body_bytes_sent=body_bytes,
            request_time=0.0,
        )
    except Exception as e:
        logger.debug(f"Line {line_no}: parse error: {e}")
        return None


def parse_csv_row(row: dict, line_no: int = 0) -> Optional[LogEvent]:
    """
    Parse a CSV row (as dict from csv.DictReader) into a LogEvent.
    Expects columns matching our LogEvent schema.
    """
    try:
        method_str = str(row.get("method", "GET")).upper().strip()
        if method_str not in _VALID_METHODS:
            return None

        # Flexible timestamp parsing
        raw_ts = row.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(raw_ts)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        bytes_sent = row.get("body_bytes_sent", "0") or "0"
        req_time = row.get("request_time", "0.0") or "0.0"

        return LogEvent(
            timestamp=ts,
            remote_ip=str(row.get("remote_ip", "")).strip(),
            method=HTTPMethod(method_str),
            url=str(row.get("url", row.get("path", "/"))).strip(),
            status=int(row.get("status_code", row.get("status", 200))),
            user_agent=row.get("user_agent") or None,
            referer=row.get("referer") or None,
            body_bytes_sent=int(bytes_sent) if str(bytes_sent).isdigit() else 0,
            request_time=float(req_time) if req_time else 0.0,
        )
    except Exception as e:
        logger.debug(f"CSV row {line_no}: parse error: {e}")
        return None


def stream_nginx_events(content: str):
    """
    Generator: yields (line_no, LogEvent | None) for each line in nginx log content.
    """
    for i, line in enumerate(content.splitlines(), start=1):
        yield i, parse_nginx_line(line, i)


def stream_csv_events(content: str):
    """
    Generator: yields (line_no, LogEvent | None) for each data row in CSV content.
    Skips the header row automatically.
    """
    reader = csv.DictReader(io.StringIO(content))
    for i, row in enumerate(reader, start=2):  # start=2 because row 1 is header
        yield i, parse_csv_row(row, i)
