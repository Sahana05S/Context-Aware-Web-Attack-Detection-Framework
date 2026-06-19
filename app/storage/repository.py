"""
Storage repository for CRUD operations.
Handles low-level database interactions.
"""
import json
import logging
from typing import Dict, Any, List, Optional
from app.models import LogEvent
from app.core.config import settings
from .db import get_db_connection

logger = logging.getLogger(__name__)


class StorageRepository:
    """Repository for storing detection results"""
    
    def __init__(self):
        pass

    @property
    def conn(self):
        return get_db_connection()

    def _stmt(self, query: str) -> str:
        """Helper to format placeholders according to DATABASE_TYPE"""
        if settings.DATABASE_TYPE == "postgresql":
            return query.replace('?', '%s')
        return query

    def insert_event(self, event: LogEvent) -> int:
        """Insert event and return ID"""
        cursor = self.conn.cursor()
        
        sql = """
        INSERT INTO events (
            timestamp, remote_ip, method, url, path, status, user_agent, request_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        params = (
            str(event.timestamp),
            event.remote_ip,
            str(event.method if not hasattr(event.method, 'value') else event.method.value or "GET")[:10],
            (event.url or "")[:2048],
            (event.url.split('?', 1)[0] if event.url else "")[:512],
            event.status,
            (event.user_agent or "")[:1024],
            None
        )
        
        if settings.DATABASE_TYPE == "postgresql":
            sql_pg = sql.replace('?', '%s') + " RETURNING id"
            cursor.execute(sql_pg, params)
            return cursor.fetchone()[0]
        else:
            cursor.execute(sql, params)
            return cursor.lastrowid

    def insert_rule_match(self, event_id: int, match: dict):
        """Insert rule match. Derives attack_type from tags list (first tag)."""
        tags = match.get('tags', [])
        attack_type = tags[0] if tags else match.get('attack_type') or match.get('rule_id', 'unknown')

        cursor = self.conn.cursor()
        cursor.execute(
            self._stmt("""
            INSERT INTO rule_matches (
                event_id, rule_id, severity, confidence, attack_type, evidence
            ) VALUES (?, ?, ?, ?, ?, ?)
            """),
            (
                event_id,
                match.get('rule_id'),
                str(match.get('severity', 'LOW')),
                float(match.get('confidence', 0.5)),
                str(attack_type)[:100],
                str(match.get('evidence', ''))[:500]
            )
        )

    def insert_behavior_flag(self, event_id: int, flag: Dict[str, Any]):
        """Insert behavior flag"""
        cursor = self.conn.cursor()
        cursor.execute(
            self._stmt("""
            INSERT INTO behavior_flags (
                event_id, remote_ip, flag_id, severity, confidence, evidence, window_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """),
            (
                event_id,
                flag.get('remote_ip', 'unknown'),
                flag.get('flag_id'),
                flag.get('severity'),
                flag.get('confidence', 1.0),
                str(flag.get('evidence', ''))[:120],
                flag.get('window_seconds', 0)
            )
        )

    def insert_ml_score(self, event_id: int, ml_output: Dict[str, Any]):
        """Insert ML score"""
        cursor = self.conn.cursor()
        cursor.execute(
            self._stmt("""
            INSERT INTO ml_scores (
                event_id, ml_score, ml_label, explanation, model_used
            ) VALUES (?, ?, ?, ?, ?)
            """),
            (
                event_id,
                ml_output.get('ml_score', 0.0),
                ml_output.get('ml_label', 'LOW'),
                str(ml_output.get('explanation', ''))[:500],
                1 if ml_output.get('model_used') else 0
            )
        )

    def insert_risk_result(self, event_id: int, risk: Dict[str, Any]):
        """Insert risk result"""
        cursor = self.conn.cursor()
        cursor.execute(
            self._stmt("""
            INSERT INTO risk_results (
                event_id, risk_score, severity, confidence, reasons_json, signals_json, correlation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """),
            (
                event_id,
                risk.get('risk_score', 0),
                risk.get('severity', 'LOW'),
                risk.get('confidence', 0.0),
                json.dumps(risk.get('reasons', []))[:1000],
                json.dumps(risk.get('signals', {}))[:500],
                json.dumps(risk.get('correlation', {}))[:500]
            )
        )

    def insert_alert(
        self, event_id: int, remote_ip: str, severity: str, risk_score: int, 
        title: str, summary: str, url: Optional[str] = None, 
        user_agent: Optional[str] = None, ai_explanation: Optional[str] = None, 
        signal_breakdown: Optional[str] = None
    ):
        """Insert generated alert"""
        cursor = self.conn.cursor()
        cursor.execute(
            self._stmt("""
            INSERT INTO alerts (
                event_id, remote_ip, severity, risk_score, title, summary,
                url, user_agent, ai_explanation, signal_breakdown
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """),
            (
                event_id,
                remote_ip,
                severity,
                risk_score,
                title,
                summary[:500],
                url,
                user_agent,
                ai_explanation,
                signal_breakdown
            )
        )
