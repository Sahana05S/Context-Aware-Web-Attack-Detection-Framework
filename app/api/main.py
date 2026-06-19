"""
Main FastAPI application for module 8.
Exposes dashboard API endpoints.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.api.routers import health_router, alerts_router, stats_router, ips_router, ingest_router, live_router, analyze_router
from app.api.routers.auth import router as auth_router
from app.api.deps import get_current_user
from fastapi import Depends

import logging
from app.storage.db import get_db_connection

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Context-Aware Web Attack Detection Framework API",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

@app.on_event("startup")
def startup_event():
    """Initialize database connection and create schema sequentially on startup."""
    logger.info("Initializing database connection and schema...")
    try:
        get_db_connection()
        logger.info("Database initialized successfully on startup.")
    except Exception as e:
        logger.error(f"Failed to initialize database on startup: {e}")

# CORS Configuration
origins = [
    "http://localhost:5173",  # Vite default
    "http://localhost:3000",  # Create React App default
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# Add allowed origins from settings
if settings.ALLOWED_ORIGINS and settings.ALLOWED_ORIGINS != "*":
    for origin in settings.ALLOWED_ORIGINS.split(","):
        clean_origin = origin.strip()
        if clean_origin and clean_origin not in origins:
            origins.append(clean_origin)

allow_all_origins = settings.ALLOWED_ORIGINS == "*"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allow_all_origins else origins,
    allow_credentials=False if allow_all_origins else True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception Handlers
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    """
    Global exception handler to return safe JSON errors.
    Prevents stack traces from leaking to client.
    """
    # Log the error safely (internal logs)
    # logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"},
    )

# Include Routers
# All dashboard endpoints under /api/v1
app.include_router(health_router, prefix="/api/v1", tags=["Health"])
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])

# Protect dashboard specific endpoints
protected_deps = [Depends(get_current_user)]

app.include_router(alerts_router, prefix="/api/v1", tags=["Alerts"], dependencies=protected_deps)
app.include_router(stats_router, prefix="/api/v1", tags=["Stats"], dependencies=protected_deps)
app.include_router(ips_router, prefix="/api/v1", tags=["IPs"], dependencies=protected_deps)
app.include_router(ingest_router, prefix="/api/v1", tags=["Ingest"]) # Usually unauthenticated if used by external agents, but we can protect it too. For now let's leave ingest public or API key based, keep it simple.
app.include_router(live_router, prefix="/api/v1", tags=["Live"], dependencies=protected_deps)
app.include_router(analyze_router, prefix="", tags=["AI Analysis"], dependencies=protected_deps)
