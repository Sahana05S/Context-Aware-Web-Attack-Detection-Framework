from .health import router as health_router
from .alerts import router as alerts_router
from .stats import router as stats_router
from .ips import router as ips_router
from .ingest import router as ingest_router
from .live import router as live_router
from .analyze import router as analyze_router

__all__ = ["health_router", "alerts_router", "stats_router", "ips_router", "ingest_router", "live_router", "analyze_router"]

