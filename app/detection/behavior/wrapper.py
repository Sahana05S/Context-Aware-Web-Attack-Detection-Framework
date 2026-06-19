"""
Behavioral detection engine wrapper for Module 6 integration.
Provides class-based API over function-based behavior detection.
"""
import logging
from typing import List, Optional
from datetime import datetime
from app.models import LogEvent
from app.detection.utils.urltools import normalize_for_matching
from .state import get_activity_store, IPActivityStore
from .engine import check_ip_behavior as check_ip_behavior_func
from .models import BehaviorMatch

logger = logging.getLogger(__name__)


class BehaviorEngine:
    """
    Thin wrapper over function-based behavior detection.
    
    Provides:
    - observe(event): Add event to activity store
    - check(event): Run behavior detection for event's IP
    
    This is a minimal adapter to maintain Module 6's expected API
    without duplicating behavior logic.
    """
    
    def __init__(self):
        """Initialize behavior engine with singleton activity store"""
        self.state_store: IPActivityStore = get_activity_store()
        logger.info("BehaviorEngine wrapper initialized")
    
    def observe(self, event: LogEvent, derived: dict) -> None:
        """
        Observe an event (add to activity store).
        
        MUST be called before check() to ensure behavioral context exists.
        
        Args:
            event: Log event to observe
            derived: Derived context (may contain normalized_ua)
        
        Security:
            - All fields safely normalized and bounded
            - Guards against None/missing values
        """
        try:
            # Safely extract method (handles both string and enum)
            method = str(event.method or "GET")[:10]
            
            # Safely extract path with None guard
            path = (derived.get("path") or (event.url.split("?", 1)[0] if event.url else ""))[:512]
            
            # Safely get normalized UA (compute if missing)
            normalized_ua = derived.get("normalized_ua")
            if not normalized_ua:
                normalized_ua = normalize_for_matching(event.user_agent or "", max_len=256)
            else:
                normalized_ua = normalized_ua[:256]
            
            # Ensure status is int
            status = event.status if isinstance(event.status, int) else 0
            
            self.state_store.add_event(
                remote_ip=event.remote_ip,
                timestamp=event.timestamp,
                path=path,
                status=status,
                method=method,
                normalized_ua=normalized_ua
            )
        except Exception as e:
            logger.error(f"Failed to observe event: {e}")
    
    def check(self, event: LogEvent) -> List[BehaviorMatch]:
        """
        Check behavioral flags for event's IP.
        
        Args:
            event: Log event to check
        
        Returns:
            List of triggered BehaviorMatch flags
        
        Security:
            - Fail-safe: returns empty list on error
        """
        try:
            matches = check_ip_behavior_func(
                ip=event.remote_ip,
                state_store=self.state_store,
                current_time=event.timestamp
            )
            return matches if matches else []
        except Exception as e:
            logger.error(f"Behavior check failed for IP {event.remote_ip}: {e}")
            return []
    
    def check_ip_behavior(self, event: LogEvent, derived: dict) -> List[BehaviorMatch]:
        """
        Combined observe + check operation.
        
        This method exists for backward compatibility with Module 6 integration.
        It observes the event THEN checks behavior.
        
        Args:
            event: Log event
            derived: Derived context
        
        Returns:
            List of BehaviorMatch flags
        """
        # First observe the event
        self.observe(event, derived)
        
        # Then check behavior
        return self.check(event)
