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

app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Context-Aware Web Attack Detection Framework API",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Configuration
origins = [
    "http://localhost:5173",  # Vite default
    "http://localhost:3000",  # Create React App default
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# Add configurable origins if needed provided via env
# For now, we stick to safe defaults for development.

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
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
