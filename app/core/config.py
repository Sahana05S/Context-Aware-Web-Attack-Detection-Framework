"""
Configuration management using pydantic-settings.
All configurations are loaded from environment variables.
"""
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "Context-Aware Web Attack Detection Framework"
    debug: bool = False
    
    # Log file configuration
    log_file_path: Path = Path("logs/access.log")
    log_root_dir: Path = Path("d:/logs/nginx")
    
    # Behavioral Detection Settings
    max_events_per_ip: int = 500
    ip_eviction_minutes: int = 30
    
    # Behavioral Detection Thresholds
    burst_10s_threshold: int = 20
    burst_60s_threshold: int = 100
    scan_60s_threshold: int = 30
    high_404_threshold: int = 20
    bruteforce_5m_threshold: int = 15
    
    # Module 3.1: Industry Realism Patches
    ignore_static_assets: bool = True
    include_redirects_in_auth: bool = False
    baseline_mode: bool = False
    baseline_min_events: int = 200
    
    # Module 7: Storage
    DATABASE_PATH: str = "./data/security.db"
    ALERT_RISK_THRESHOLD: int = 25

    # AI Intent Analyzer
    AI_API_KEY: str = ""
    AI_MODEL: str = "llama-3.1-8b-instant"
    AI_ENABLED: bool = True

    # Flow / Session Detection
    FLOW_DETECTION_ENABLED: bool = True
    FLOW_SESSION_TIMEOUT: int = 300

    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


# Global settings instance
settings = Settings()
