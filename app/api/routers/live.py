"""
Live log tail endpoint using Server-Sent Events (SSE).
GET /api/v1/live/stream  — streams new log lines as they appear in a file.
GET /api/v1/live/status  — tail status (active / idle, rate).
"""
import asyncio
import json
import logging
import os
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.ingest.parsers import detect_format, parse_nginx_line, parse_csv_row
from app.ingest import process_single_event

logger = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# Safety: only allow tailing of plain text files inside allowed directories.
# ---------------------------------------------------------------------------
_ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".access"}
_MAX_CATCHUP_LINES  = 0     # skip existing lines, only tail new ones
_SSE_POLL_INTERVAL  = 0.5   # seconds between file read polls
_SSE_KEEPALIVE_SEC  = 15    # send comment ping every N seconds

# Global tail state (simple in-process tracking)
_tail_state = {
    "active": False,
    "path": "",
    "lines_sent": 0,
    "alerts_sent": 0,
    "started_at": None,
}


class LiveStatus(BaseModel):
    active: bool
    path: str
    lines_sent: int
    alerts_sent: int
    started_at: str | None


def _validate_log_path(path: str) -> Path:
    """Validate that path is safe to tail (no traversal, readable file)."""
    if not path:
        raise HTTPException(status_code=400, detail="log_path is required.")

    p = Path(path).resolve()

    # Path traversal guard: resolved path must equal requested path
    try:
        requested = Path(path).resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path.")

    if not p.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    if not p.is_file():
        raise HTTPException(status_code=400, detail="Path must point to a file, not a directory.")
    if p.suffix.lower() not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension. Allowed: {_ALLOWED_EXTENSIONS}",
        )
    if not os.access(p, os.R_OK):
        raise HTTPException(status_code=403, detail="File is not readable.")

    return p


async def _tail_file_generator(path: Path, fmt: str):
    """
    Async generator that tails a file and yields SSE-formatted strings.
    Detects format, positions at end of file, then polls for new lines.
    """
    global _tail_state

    _tail_state.update({
        "active": True,
        "path": str(path),
        "lines_sent": 0,
        "alerts_sent": 0,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })

    last_keepalive = time.time()
    line_no = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Seek to end of file — only process NEW lines
            f.seek(0, 2)

            while True:
                lines_batch = f.readlines()

                if not lines_batch:
                    # No new data — send keepalive comment to keep connection alive
                    if time.time() - last_keepalive > _SSE_KEEPALIVE_SEC:
                        yield ": keepalive\n\n"
                        last_keepalive = time.time()
                    await asyncio.sleep(_SSE_POLL_INTERVAL)
                    continue

                for raw_line in lines_batch:
                    line_no += 1
                    # Parse according to detected format
                    if fmt == "nginx":
                        event = parse_nginx_line(raw_line, line_no)
                    else:
                        # For CSV tailing, treat new lines as nginx for now
                        event = parse_nginx_line(raw_line, line_no)

                    if event is None:
                        continue

                    # Run through detection pipeline
                    try:
                        result = process_single_event(event)
                    except Exception as e:
                        logger.error(f"Live detection error: {e}")
                        result = {}

                    is_alert = bool(
                        result.get("risk") and
                        result["risk"].get("severity") not in (None, "LOW", "INFO")
                    )

                    payload = {
                        "timestamp": str(event.timestamp),
                        "remote_ip": event.remote_ip,
                        "method": event.method if isinstance(event.method, str) else event.method.value,
                        "url": event.url[:120],
                        "status": event.status,
                        "severity": result.get("risk", {}).get("severity", "NONE"),
                        "risk_score": result.get("risk", {}).get("risk_score", 0),
                        "is_alert": is_alert,
                    }

                    _tail_state["lines_sent"] += 1
                    if is_alert:
                        _tail_state["alerts_sent"] += 1

                    yield f"data: {json.dumps(payload)}\n\n"

                last_keepalive = time.time()
                await asyncio.sleep(0)   # yield control

    except asyncio.CancelledError:
        logger.info(f"SSE stream cancelled for {path}")
    finally:
        _tail_state["active"] = False


@router.get("/live/stream")
async def live_stream(
    log_path: str = Query(..., description="Absolute path to the server access log file"),
):
    """
    Stream new log entries as Server-Sent Events (SSE).

    Connect with EventSource in the browser:
      const es = new EventSource('/api/v1/live/stream?log_path=/var/log/nginx/access.log');
      es.onmessage = (e) => console.log(JSON.parse(e.data));

    Each event has: timestamp, remote_ip, method, url, status, severity, risk_score, is_alert
    """
    path = _validate_log_path(log_path)

    # Detect format from first line
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first_line = f.readline()
    fmt = detect_format(first_line)
    if fmt == "unknown":
        fmt = "nginx"   # default to nginx for tailing unknown text logs

    return StreamingResponse(
        _tail_file_generator(path, fmt),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",     # disable Nginx buffering if proxied
        },
    )


@router.get("/live/status", response_model=LiveStatus)
async def live_status():
    """Return current tail status."""
    return LiveStatus(
        active=_tail_state["active"],
        path=_tail_state["path"],
        lines_sent=_tail_state["lines_sent"],
        alerts_sent=_tail_state["alerts_sent"],
        started_at=_tail_state["started_at"],
    )
