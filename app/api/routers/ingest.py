"""
Log file upload endpoint.
POST /api/v1/ingest/upload — accepts Nginx or CSV log file, runs detection pipeline.
DELETE /api/v1/ingest/clear  — wipe all stored detection data.
"""
import logging
from typing import Annotated

from fastapi import APIRouter, File, UploadFile, HTTPException
from pydantic import BaseModel

from app.ingest.parsers import detect_format, stream_nginx_events, stream_csv_events
from app.ingest import process_single_event
from app.storage.db import get_db_connection


logger = logging.getLogger(__name__)
router = APIRouter()

MAX_FILE_BYTES = 50 * 1024 * 1024   # 50 MB
MAX_LINES      = 100_000             # safety cap


class UploadResult(BaseModel):
    filename: str
    format_detected: str
    total_lines: int
    processed: int
    skipped: int
    errors: int
    alerts_triggered: int


@router.post("/ingest/upload", response_model=UploadResult)
async def upload_log_file(
    file: Annotated[UploadFile, File(description="Nginx/Apache combined log or CSV file")]
):
    """
    Upload a server access log file and run it through the detection pipeline.

    Supported formats:
    - Nginx / Apache combined log (auto-detected)
    - CSV with columns: timestamp, remote_ip, method, url, status_code, user_agent

    Returns a summary of processing results.
    """
    # -- Size guard --
    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_FILE_BYTES // (1024*1024)} MB.",
        )

    # -- Decode safely --
    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as UTF-8.")

    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # -- Detect format --
    first_line = content.splitlines()[0] if content.splitlines() else ""
    fmt = detect_format(first_line)
    if fmt == "unknown":
        raise HTTPException(
            status_code=422,
            detail=(
                "Could not detect log format. "
                "Expected Nginx/Apache combined log or CSV with header row "
                "(timestamp, remote_ip, method, url, status_code, user_agent)."
            ),
        )

    # -- Stream through pipeline --
    total_lines = processed = skipped = errors = alerts = 0
    generator = stream_nginx_events(content) if fmt == "nginx" else stream_csv_events(content)

    conn = get_db_connection()
    try:
        with conn:
            for line_no, event in generator:
                total_lines += 1
                if total_lines > MAX_LINES:
                    logger.warning(f"Upload cap reached at {MAX_LINES} lines, stopping.")
                    break

                if event is None:
                    skipped += 1
                    continue

                try:
                    result = process_single_event(event, commit=False)
                    processed += 1
                    if result.get("risk") and result["risk"].get("severity") not in (None, "LOW", "INFO"):
                        alerts += 1
                except Exception as e:
                    logger.error(f"Processing error at line {line_no}: {e}")
                    errors += 1
    except Exception as e:
        logger.error(f"Database transaction error during upload: {e}")
        # Explicit raise to notify API client of transaction failure
        raise HTTPException(status_code=500, detail=f"Database transaction error during upload: {e}")

    return UploadResult(
        filename=file.filename or "unknown",
        format_detected=fmt,
        total_lines=total_lines,
        processed=processed,
        skipped=skipped,
        errors=errors,
        alerts_triggered=alerts,
    )


@router.delete("/ingest/clear")
async def clear_detection_data():
    """
    Wipe all stored detection data from the database.
    Useful for starting fresh before a new upload session.
    """
    try:
        conn = get_db_connection()
        tables = ["alerts", "behavior_flags", "ml_scores", "risk_results", "rule_matches", "events"]
        for table in tables:
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        return {"cleared": True, "message": "All detection data has been removed."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear data: {e}")
