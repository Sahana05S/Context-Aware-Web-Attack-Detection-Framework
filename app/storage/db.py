"""
Database connection and initialization for storage layer.
Handles SQLite connection singleton and schema creation.
"""
import os
import sqlite3
import logging
from typing import Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

# Singleton connection
_connection: Optional[sqlite3.Connection] = None


def get_db_connection() -> sqlite3.Connection:
    """
    Get singleton database connection.
    Creates tables if they don't exist.
    """
    global _connection
    
    if _connection is None:
        try:
            # Ensure directory exists
            db_dir = os.path.dirname(settings.DATABASE_PATH)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            
            # Connect
            _connection = sqlite3.connect(
                settings.DATABASE_PATH,
                check_same_thread=False  # Allow multi-threaded use (with caution)
            )
            
            # Enable foreign keys
            _connection.execute("PRAGMA foreign_keys = ON;")
            
            # Enable WAL mode and normal synchronous for concurrency and performance
            _connection.execute("PRAGMA journal_mode = WAL;")
            _connection.execute("PRAGMA synchronous = NORMAL;")
            
            # Use row factory for dict-like access if needed, 
            # but standard cursor is fine for now.
            
            # Initialize schema
            _create_schema(_connection)
            
            logger.info(f"Connected to database at {settings.DATABASE_PATH}")
            
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    return _connection


def _create_schema(conn: sqlite3.Connection) -> None:
    """Create database schema if not exists"""
    cursor = conn.cursor()
    
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
        # Check if url column exists (as proxy for the new columns)
        cursor.execute("PRAGMA table_info(alerts)")
        columns = [col[1] for col in cursor.fetchall()]
        if "url" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN url TEXT;")
            cursor.execute("ALTER TABLE alerts ADD COLUMN user_agent TEXT;")
            cursor.execute("ALTER TABLE alerts ADD COLUMN ai_explanation TEXT;")
            cursor.execute("ALTER TABLE alerts ADD COLUMN signal_breakdown TEXT;")
            logger.info("Migrated alerts table with new explanation columns.")
    except Exception as e:
        logger.error(f"Migration error: {e}")

    conn.commit()


def close_db_connection():
    """Close database connection"""
    global _connection
    if _connection:
        _connection.close()
        _connection = None
