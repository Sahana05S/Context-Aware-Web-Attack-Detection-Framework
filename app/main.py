"""
FastAPI application entry point for the Context-Aware Web Attack Detection Framework.
Module 1: Secure Nginx log ingestion and parsing.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.services import LogIngestor
from app.services.ingestor import HARD_MAX_EVENTS, DEFAULT_MAX_EVENTS
from app.models import LogEvent


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info(f"Starting {settings.app_name}")
    logger.info(f"Log file path: {settings.log_file_path}")
    logger.info(f"Log root directory: {settings.log_root_dir}")
    
    # Verify log file is accessible
    try:
        if settings.log_file_path.exists():
            ingestor = LogIngestor(settings.log_file_path)
            logger.info("Log ingestor initialized successfully")
        else:
            logger.warning(f"Log file not found: {settings.log_file_path}")
            logger.info("Create the log file or update LOG_FILE_PATH in .env")
    except Exception as e:
        logger.error(f"Failed to initialize log ingestor: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")


# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    description="Context-Aware Web Attack Detection Framework - Module 1: Log Ingestion",
    version="0.1.0",
    lifespan=lifespan
)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": settings.app_name,
        "module": "Log Ingestion",
        "status": "operational",
        "version": "0.1.0"
    }


@app.get("/api/v1/logs/ingest")
async def ingest_logs(limit: int = DEFAULT_MAX_EVENTS):
    """
    Ingest and parse logs from the configured log file.
    
    Args:
        limit: Maximum number of log entries to return (default: 100, max: 200)
    
    Returns:
        JSON response with parsed log events
    
    Security:
    - Read-only access to log file
    - Input validation via Pydantic
    - Limit parameter capped at HARD_MAX_EVENTS (200)
    - Returns only validated, sanitized LogEvent objects
    """
    try:
        # Security: Enforce hard cap on limit
        if limit < 1:
            raise HTTPException(
                status_code=400,
                detail=f"Limit must be at least 1"
            )
        
        if limit > HARD_MAX_EVENTS:
            raise HTTPException(
                status_code=400,
                detail=f"Limit exceeds maximum allowed ({HARD_MAX_EVENTS})"
            )
        
        # Initialize ingestor
        ingestor = LogIngestor(settings.log_file_path)
        
        # Read and parse logs (limit is enforced by ingestor)
        events = []
        for event in ingestor.read_logs(max_events=limit):
            events.append(event.model_dump())
        
        return {
            "success": True,
            "count": len(events),
            "limit": limit,
            "events": events
        }
    
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Log file not found: {settings.log_file_path}"
        )
    except Exception as e:
        logger.error(f"Error during log ingestion: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Log ingestion failed: {str(e)}"
        )


@app.get("/api/v1/logs/stats")
async def get_log_stats():
    """
    Get statistics about the log file.
    
    Returns:
        JSON with log file statistics (total lines, valid events, errors)
    """
    try:
        ingestor = LogIngestor(settings.log_file_path)
        
        total_lines = 0
        valid_events = 0
        
        # Read all available events (up to HARD_MAX_EVENTS for stats)
        for event in ingestor.read_logs(max_events=HARD_MAX_EVENTS):
            total_lines += 1
            if event:
                valid_events += 1
        
        return {
            "success": True,
            "log_file": str(settings.log_file_path),
            "total_events_scanned": total_lines,
            "valid_events": valid_events,
            "note": f"Stats limited to first {HARD_MAX_EVENTS} events"
        }
    
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Log file not found: {settings.log_file_path}"
        )
    except Exception as e:
        logger.error(f"Error getting log stats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get log statistics: {str(e)}"
        )


@app.get("/api/v1/detections/rules")
async def run_detections(limit: int = DEFAULT_MAX_EVENTS):
    """
    Run detection rules on recent log events.
    
    Args:
        limit: Maximum number of events to analyze (default: 100, max: 200)
    
    Returns:
        JSON with matched events and detection statistics
    
    Security:
        - Limit capped at HARD_MAX_EVENTS
        - Only returns events with at least one match
        - Evidence is sanitized
    """
    try:
        # Import detection components
        from app.detection.rules.registry import get_registry
        from app.detection.rules.engine import run_on_events, get_detection_stats
        
        # Security: Enforce hard cap on limit
        if limit < 1:
            raise HTTPException(
                status_code=400,
                detail="Limit must be at least 1"
            )
        
        if limit > HARD_MAX_EVENTS:
            raise HTTPException(
                status_code=400,
                detail=f"Limit exceeds maximum allowed ({HARD_MAX_EVENTS})"
            )
        
        # Read events
        ingestor = LogIngestor(settings.log_file_path)
        events = []
        for event in ingestor.read_logs(max_events=limit):
            events.append(event)
        
        # Get enabled rules
        registry = get_registry()
        enabled_rules = registry.get_enabled_rules()
        
        # Run detection
        results = run_on_events(events, enabled_rules)
        stats = get_detection_stats(results)
        
        return {
            "success": True,
            "events_analyzed": len(events),
            "matched_events": len(results),
            "statistics": stats,
            "detections": results
        }
    
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Log file not found: {settings.log_file_path}"
        )
    except Exception as e:
        logger.error(f"Error running detections: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Detection failed: {str(e)}"
        )


@app.get("/api/v1/detections/behavior")
async def run_behavior_detection_endpoint(limit: int = DEFAULT_MAX_EVENTS):
    """
    Run behavioral detection on recent log events.
    
    Tracks per-IP patterns over time to detect:
    - Request bursts (10s, 60s windows)
    - Endpoint scanning
    - High 404 rates
    - Login brute force
    - Automation/tool usage
    
    Args:
        limit: Maximum number of events to analyze (default: 100, max: 200)
    
    Returns:
        JSON with per-IP behavioral flags and statistics
    
    Security:
        - Limit capped at HARD_MAX_EVENTS
        - State store has memory bounds (500 events/IP)
        - Evidence sanitized
    """
    try:
        from app.services.ingestor import read_log_file
        from app.detection.behavior.state import get_activity_store
        from app.detection.behavior.engine import run_behavior_detection
        
        # Validate and cap limit
        if limit < 1:
            raise HTTPException(
                status_code=400,
                detail="Limit must be at least 1"
            )

        # Cap limit for safety
        limit = min(limit, HARD_MAX_EVENTS)
        
        # Get events
        events = read_log_file(limit=limit)
        
        # Get singleton activity store
        activity_store = get_activity_store()
        
        # Run behavioral detection
        results = run_behavior_detection(events, activity_store)
        
        return {
            "success": True,
            "events_analyzed": len(events),
            "ips_flagged": results["statistics"]["ips_flagged"],
            "statistics": results["statistics"],
            "detections": results["detections"]
        }
    
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Log file not found")
    except Exception as e:
        logger.error(f"Behavioral detection error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/detections/ml")
async def run_ml_detection_endpoint(limit: int = DEFAULT_MAX_EVENTS):
    """
    Run ML-based detection scoring on recent log events.
    
    Returns:
        - events_analyzed: Number of events processed
        - model_loaded: Whether ML model is available
        - statistics: HIGH/MEDIUM/LOW counts
        - top_suspicious: Top suspicious events (max 50)
    """
    try:
        from app.services.ingestor import read_log_file
        from app.detection.ml import MLScorer
        from app.detection.engine import detect_attacks
        
        # Cap limit for safety
        limit = min(limit, HARD_MAX_EVENTS)
        
        # Get events
        events = read_log_file(limit=limit)
        
        # Initialize scorer
        scorer = MLScorer()
        
        # Score each event
        scored_events = []
        for event in events:
            # Get derived context from rules (for feature extraction)
            try:
                rule_matches = detect_attacks([event])
                derived = rule_matches[0] if rule_matches else {}
            except Exception:
                derived = {}
            
            # Score event
            score_result = scorer.score_event(event, derived)
            
            scored_events.append({
                "timestamp": event.timestamp.isoformat(),
                "remote_ip": event.remote_ip,
                "url": event.url[:200],  # Truncate URL for response
                "status": event.status,
                "method": event.method,
                **score_result
            })
        
        # Calculate statistics
        high_count = sum(1 for e in scored_events if e["ml_label"] == "HIGH")
        medium_count = sum(1 for e in scored_events if e["ml_label"] == "MEDIUM")
        low_count = sum(1 for e in scored_events if e["ml_label"] == "LOW")
        
        # Get top suspicious events (max 50)
        top_suspicious = sorted(
            scored_events,
            key=lambda x: x["ml_score"],
            reverse=True
        )[:50]
        
        return {
            "success": True,
            "events_analyzed": len(events),
            "model_loaded": scorer.model_loaded,
            "statistics": {
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count
            },
            "top_suspicious": top_suspicious
        }
    
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Log file not found")
    except Exception as e:
        logger.error(f"ML detection error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug
    )
