"""
Rolling state store for per-IP behavioral analysis.
Maintains bounded in-memory history of events per IP address.
"""
import logging
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class IPActivityStore:
    """
    In-memory rolling window store for IP activity tracking.
    
    Maintains per-IP event history with:
    - Memory bounds (max events per IP)
    - Automatic eviction of inactive IPs
    - Time-windowed queries
    
    Thread-safety: Not thread-safe (use locks if needed for concurrent access)
    """
    
    def __init__(
        self,
        max_events_per_ip: int = 500,
        eviction_minutes: int = 30
    ):
        """
        Initialize activity store.
        
        Args:
            max_events_per_ip: Maximum events to store per IP
            eviction_minutes: Minutes of inactivity before IP eviction
        """
        self.max_events_per_ip = max_events_per_ip
        self.eviction_minutes = eviction_minutes
        
        # Storage: {ip: {"events": deque, "last_activity": datetime}}
        self._store: Dict[str, dict] = {}
    
    def add_event(
        self,
        remote_ip: str,
        timestamp: datetime,
        path: str,
        status: int,
        method: str,
        normalized_ua: str
    ) -> None:
        """
        Add an event to the store.
        
        Args:
            remote_ip: Client IP address
            timestamp: Event timestamp
            path: Request path
            status: HTTP status code
            method: HTTP method
            normalized_ua: Normalized user agent
        
        Security:
            - Enforces max_events_per_ip cap (FIFO eviction)
            - Bounds all string fields
        """
        # Normalize timezone to system local naive datetime for consistent comparisons
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone().replace(tzinfo=None)

        # Initialize IP entry if needed
        if remote_ip not in self._store:
            self._store[remote_ip] = {
                "events": deque(maxlen=self.max_events_per_ip),
                "last_activity": timestamp
            }
        
        # Add event (deque automatically evicts oldest if at maxlen)
        event_data = {
            "timestamp": timestamp,
            "path": path[:512],  # Cap path length
            "status": status,
            "method": method[:10],  # Cap method length
            "normalized_ua": normalized_ua[:256]  # Cap UA length
        }
        
        self._store[remote_ip]["events"].append(event_data)
        self._store[remote_ip]["last_activity"] = timestamp
    
    def get_events(
        self,
        remote_ip: str,
        window_seconds: int,
        current_time: Optional[datetime] = None
    ) -> List[dict]:
        """
        Get events for an IP within a time window.
        
        Args:
            remote_ip: Client IP address
            window_seconds: Time window in seconds
            current_time: Reference time (defaults to now)
        
        Returns:
            List of event dicts within the window (oldest first)
        """
        if remote_ip not in self._store:
            return []
        
        if current_time is None:
            current_time = datetime.now()
        elif current_time.tzinfo is not None:
            current_time = current_time.astimezone().replace(tzinfo=None)
        
        cutoff_time = current_time - timedelta(seconds=window_seconds)
        
        # Filter events within window
        all_events = self._store[remote_ip]["events"]
        windowed_events = [
            event for event in all_events
            if event["timestamp"] >= cutoff_time
        ]
        
        return windowed_events
    
    def evict_inactive(self, current_time: Optional[datetime] = None) -> int:
        """
        Evict IPs that have been inactive beyond threshold.
        
        Args:
            current_time: Reference time (defaults to now)
        
        Returns:
            Number of IPs evicted
        """
        if current_time is None:
            current_time = datetime.now()
        elif current_time.tzinfo is not None:
            current_time = current_time.astimezone().replace(tzinfo=None)
        
        eviction_threshold = current_time - timedelta(minutes=self.eviction_minutes)
        
        ips_to_evict = [
            ip for ip, data in self._store.items()
            if data["last_activity"] < eviction_threshold
        ]
        
        for ip in ips_to_evict:
            del self._store[ip]
        
        if ips_to_evict:
            logger.info(f"Evicted {len(ips_to_evict)} inactive IPs")
        
        return len(ips_to_evict)
    
    def get_ip_count(self) -> int:
        """Get number of tracked IPs"""
        return len(self._store)
    
    def get_total_events(self) -> int:
        """Get total number of events across all IPs"""
        return sum(len(data["events"]) for data in self._store.values())
    
    def clear(self) -> None:
        """Clear all stored data"""
        self._store.clear()


# Global singleton instance
_activity_store: Optional[IPActivityStore] = None


def get_activity_store(
    max_events_per_ip: int = 500,
    eviction_minutes: int = 30
) -> IPActivityStore:
    """
    Get global activity store instance (singleton).
    
    Args:
        max_events_per_ip: Max events per IP (only used on first call)
        eviction_minutes: Eviction threshold (only used on first call)
    
    Returns:
        IPActivityStore instance
    """
    global _activity_store
    if _activity_store is None:
        _activity_store = IPActivityStore(max_events_per_ip, eviction_minutes)
    return _activity_store
