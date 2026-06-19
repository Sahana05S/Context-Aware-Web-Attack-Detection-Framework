"""
Health check router.
"""
from fastapi import APIRouter
from app.api.schemas import StatusResponse
from app.storage import get_db_connection

router = APIRouter()

@router.get("/health", response_model=StatusResponse)
def health_check():
    """
    Basic health check.
    Verifies DB connection effectively by getting a connection.
    """
    db_status = "unknown"
    try:
        conn = get_db_connection()
        conn.cursor().execute("SELECT 1")
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return StatusResponse(
        status="ok",
        db_status=db_status
    )
