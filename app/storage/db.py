"""
Database connection and initialization for storage layer.
Handles SQLite and PostgreSQL connection singleton and schema creation.
"""
import os
import sqlite3
import logging
from typing import Optional, Any
from app.core.config import settings

logger = logging.getLogger(__name__)

try:
    import psycopg2
except ImportError:
    psycopg2 = None

import threading

# Thread-local storage for connections
_thread_local = threading.local()


def get_db_connection() -> Any:
    """
    Get thread-local database connection (SQLite or PostgreSQL).
    Creates tables if they don't exist.
    """
    # Get or initialize the connection for the current thread
    conn = getattr(_thread_local, "connection", None)
    
    # Check if existing connection is closed
    connection_is_closed = False
    if conn is not None:
        if settings.DATABASE_TYPE == "postgresql":
            try:
                connection_is_closed = (conn.closed != 0)
            except AttributeError:
                connection_is_closed = True
        else:
            try:
                conn.execute("SELECT 1")
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                connection_is_closed = True

    if conn is None or connection_is_closed:
        try:
            if settings.DATABASE_TYPE == "postgresql":
                if psycopg2 is None:
                    raise ImportError(
                        "psycopg2 is not installed. Run 'pip install psycopg2-binary' to connect to PostgreSQL."
                    )
                db_url = settings.DATABASE_URL
                # Handle connection URL format for standard databases
                if db_url.startswith("postgres://"):
                    db_url = db_url.replace("postgres://", "postgresql://", 1)
                
                conn = psycopg2.connect(db_url)
                # Initialize schema
                _create_schema(conn)
                logger.info("Connected to PostgreSQL database (thread-local)")
            else:
                # Ensure directory exists
                db_dir = os.path.dirname(settings.DATABASE_PATH)
                if db_dir and not os.path.exists(db_dir):
                    os.makedirs(db_dir, exist_ok=True)
                
                # Connect
                conn = sqlite3.connect(
                    settings.DATABASE_PATH,
                    check_same_thread=False  # Allow multi-threaded use (with caution)
                )
                
                # Enable foreign keys
                conn.execute("PRAGMA foreign_keys = ON;")
                
                # Enable WAL mode and normal synchronous for concurrency and performance
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                
                # Initialize schema
                _create_schema(conn)
                logger.info(f"Connected to SQLite database at {settings.DATABASE_PATH} (thread-local)")
                
            _thread_local.connection = conn
            
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    return conn


def _create_schema(conn: Any) -> None:
    """Create database schema if not exists"""
    cursor = conn.cursor()
    
    if settings.DATABASE_TYPE == "postgresql":
        # 1. Events
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            timestamp VARCHAR(100) NOT NULL,
            remote_ip VARCHAR(100) NOT NULL,
            method VARCHAR(10) NOT NULL,
            url VARCHAR(4000) NOT NULL,
            path VARCHAR(1000) NOT NULL,
            status INTEGER,
            user_agent VARCHAR(2048),
            request_id VARCHAR(100),
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_remote_ip ON events(remote_ip);")

        # 2. Rule Matches
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_matches (
            id SERIAL PRIMARY KEY,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            rule_id VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            confidence REAL NOT NULL,
            attack_type VARCHAR(100),
            evidence VARCHAR(1000),
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rule_matches_event_id ON rule_matches(event_id);")

        # 3. Behavior Flags
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavior_flags (
            id SERIAL PRIMARY KEY,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            remote_ip VARCHAR(100) NOT NULL,
            flag_id VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            confidence REAL NOT NULL,
            evidence VARCHAR(500),
            window_seconds INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_behavior_flags_event_id ON behavior_flags(event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_behavior_flags_remote_ip ON behavior_flags(remote_ip);")

        # 4. ML Scores
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS ml_scores (
            id SERIAL PRIMARY KEY,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            ml_score REAL NOT NULL,
            ml_label VARCHAR(20) NOT NULL,
            explanation VARCHAR(1000),
            model_used INTEGER NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ml_scores_event_id ON ml_scores(event_id);")

        # 5. Risk Results
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_results (
            id SERIAL PRIMARY KEY,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            risk_score INTEGER NOT NULL,
            severity VARCHAR(20) NOT NULL,
            confidence REAL NOT NULL,
            reasons_json TEXT,
            signals_json TEXT,
            correlation_json TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_results_event_id ON risk_results(event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_results_risk_score ON risk_results(risk_score);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_results_severity ON risk_results(severity);")

        # 6. Alerts
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            remote_ip VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            risk_score INTEGER NOT NULL,
            title VARCHAR(200) NOT NULL,
            summary VARCHAR(1000) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
            url VARCHAR(2048),
            user_agent VARCHAR(1024),
            ai_explanation TEXT,
            signal_breakdown TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_remote_ip ON alerts(remote_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")

        # 7. Users
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            hashed_password VARCHAR(255) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

        # 8. Migrations (PostgreSQL check column)
        try:
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'alerts' AND column_name = 'url'
            """)
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE alerts ADD COLUMN url VARCHAR(2048);")
                cursor.execute("ALTER TABLE alerts ADD COLUMN user_agent VARCHAR(1024);")
                cursor.execute("ALTER TABLE alerts ADD COLUMN ai_explanation TEXT;")
                cursor.execute("ALTER TABLE alerts ADD COLUMN signal_breakdown TEXT;")
                logger.info("Migrated alerts table with new columns (PostgreSQL).")
        except Exception as e:
            logger.error(f"PostgreSQL Migration error: {e}")

    else:
        # 1. Events
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            path TEXT NOT NULL,
            status INTEGER,
            user_agent TEXT,
            request_id TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_remote_ip ON events(remote_ip);")

        # 2. Rule Matches
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS rule_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            attack_type TEXT,
            evidence TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rule_matches_event_id ON rule_matches(event_id);")

        # 3. Behavior Flags
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavior_flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            remote_ip TEXT NOT NULL,
            flag_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence TEXT,
            window_seconds INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_behavior_flags_event_id ON behavior_flags(event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_behavior_flags_remote_ip ON behavior_flags(remote_ip);")

        # 4. ML Scores
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS ml_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            ml_score REAL NOT NULL,
            ml_label TEXT NOT NULL,
            explanation TEXT,
            model_used INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ml_scores_event_id ON ml_scores(event_id);")

        # 5. Risk Results
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            reasons_json TEXT,
            signals_json TEXT,
            correlation_json TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_results_event_id ON risk_results(event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_results_risk_score ON risk_results(risk_score);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_results_severity ON risk_results(severity);")

        # 6. Alerts
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            remote_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            url TEXT,
            user_agent TEXT,
            ai_explanation TEXT,
            signal_breakdown TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_remote_ip ON alerts(remote_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")

        # 7. Users
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")

        # 8. Migrations (SQLite ALTER TABLE)
        try:
            cursor.execute("PRAGMA table_info(alerts)")
            columns = [col[1] for col in cursor.fetchall()]
            if "url" not in columns:
                cursor.execute("ALTER TABLE alerts ADD COLUMN url TEXT;")
                cursor.execute("ALTER TABLE alerts ADD COLUMN user_agent TEXT;")
                cursor.execute("ALTER TABLE alerts ADD COLUMN ai_explanation TEXT;")
                cursor.execute("ALTER TABLE alerts ADD COLUMN signal_breakdown TEXT;")
                logger.info("Migrated alerts table with new columns (SQLite).")
        except Exception as e:
            logger.error(f"SQLite Migration error: {e}")

    conn.commit()


def close_db_connection():
    """Close database connection for the current thread"""
    conn = getattr(_thread_local, "connection", None)
    if conn:
        try:
            conn.close()
        except Exception as e:
            logger.warning(f"Error closing database connection: {e}")
        _thread_local.connection = None
