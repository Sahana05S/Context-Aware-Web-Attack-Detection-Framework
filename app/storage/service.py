"""
Storage service orchestration.
Handles saving detection results to the database.
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.models import LogEvent
from app.core.config import settings
from .repository import StorageRepository

logger = logging.getLogger(__name__)

# Singleton service
_storage_service: Optional['StorageService'] = None


class StorageService:
    """
    High-level storage service.
    Orchestrates persistence of events and all associated detection outputs.
    """
    
    def __init__(self):
        self.repo = StorageRepository()
        self.alert_risk_threshold = settings.ALERT_RISK_THRESHOLD

    def store_detection_result(
        self,
        event: LogEvent,
        matches: List[Dict[str, Any]],
        behavior_matches: List[Dict[str, Any]],
        ml_output: Dict[str, Any],
        risk_result: Dict[str, Any],
        derived: Dict[str, Any],
        commit: bool = True
    ) -> Optional[int]:
        """
        Store full detection result (event + signals + risk).
        
        Args:
            event: LogEvent object
            matches: List of rule match dicts
            behavior_matches: List of behavior match dicts
            ml_output: ML scoring dict
            risk_result: Risk result dict (from RiskResult.model_dump())
            derived: Derived context dict
            commit: Whether to commit transaction immediately
            
        Returns:
            event_id if successful, None if failed
            
        Security:
            - Fail-safe: catches all exceptions to prevent pipeline crash
            - Parameterized queries via repo
        """
        try:
            # 1. Store event
            event_id = self.repo.insert_event(event)

            # 2. Store rule matches
            for match in matches:
                self.repo.insert_rule_match(event_id, match)

            # 3. Store behavior flags
            for flag in behavior_matches:
                # Ensure remote_ip is present
                if 'remote_ip' not in flag:
                    flag['remote_ip'] = event.remote_ip
                self.repo.insert_behavior_flag(event_id, flag)

            # 4. Store ML score
            if ml_output:
                self.repo.insert_ml_score(event_id, ml_output)

            # 5. Store risk result
            if risk_result:
                self.repo.insert_risk_result(event_id, risk_result)
                
                # 6. Check for Alerts
                self._check_and_create_alert(event_id, event, risk_result, matches, behavior_matches)

            if commit:
                self.repo.conn.commit()

            return event_id

        except Exception as e:
            logger.error(f"Failed to store detection result: {e}")
            return None

    def _check_and_create_alert(
        self,
        event_id: int,
        event: LogEvent,
        risk: Dict[str, Any],
        matches: List[Dict[str, Any]],
        behavior: List[Dict[str, Any]]
    ):
        """
        Generate alert if risk threshold met.
        Alert title is contextual: includes attack type, IP, and severity.
        """
        severity = risk.get('severity', 'LOW')
        score = risk.get('risk_score', 0)

        is_high_severity = severity in ('HIGH', 'CRITICAL')
        is_above_threshold = score >= self.alert_risk_threshold

        if is_high_severity or is_above_threshold:
            # ── Derive contextual attack name ──────────────────────────────
            # Priority: behavior flag_id > rule tags > generic
            _ATTACK_LABELS = {
                "sqli": "SQL Injection",
                "xss": "Cross-Site Scripting (XSS)",
                "traversal": "Path Traversal",
                "cmdi": "Command Injection",
                "scanner": "Automated Scanner Probe",
                "reconnaissance": "Reconnaissance",
                "lfi": "Local File Inclusion",
                "rfi": "Remote File Inclusion",
                "ssrf": "SSRF Attempt",
            }

            attack_type = "Web Attack"
            if behavior:
                flag_id = behavior[0].get('flag_id', '')
                if 'bruteforce' in flag_id:
                    attack_type = "Login Brute Force"
                elif 'burst' in flag_id or 'scan' in flag_id:
                    attack_type = "Coordinated Scan / Burst"
            elif matches:
                tags = matches[0].get('tags', [])
                for tag in tags:
                    label = _ATTACK_LABELS.get(tag.lower())
                    if label:
                        attack_type = label
                        break
                # Multiple rule matches → multi-vector
                if len(matches) > 2:
                    attack_type = f"Multi-Vector Attack ({len(matches)} signatures)"

            title = f"{attack_type} — {severity} Risk"

            # Build summary with reasons
            reasons = risk.get('reasons', [])
            reason_str = "; ".join(str(r) for r in reasons[:2])
            path = (event.url or "").split('?', 1)[0][:50]

            summary = (
                f"IP: {event.remote_ip} | Path: {path} | "
                f"Score: {score} | {reason_str}"
            )

            import json
            signal_breakdown_json = json.dumps(risk.get('signals', {}))

            self.repo.insert_alert(
                event_id=event_id,
                remote_ip=event.remote_ip,
                severity=severity,
                risk_score=score,
                title=title,
                summary=summary,
                url=event.url,
                user_agent=event.user_agent,
                ai_explanation=risk.get("ai_explanation"),
                signal_breakdown=signal_breakdown_json
            )


def get_storage_service() -> StorageService:
    """Get singleton storage service"""
    global _storage_service
    if _storage_service is None:
        _storage_service = StorageService()
    return _storage_service
