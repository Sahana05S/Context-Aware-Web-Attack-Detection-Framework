"""
Per-IP session and request flow tracker.
Models the sequence of requests an IP makes over time,
enabling detection of workflow violations and abnormal navigation.
"""
import logging
from collections import deque
from datetime import datetime, timedelta
from threading import Lock
from typing import Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

# Max events to store per IP in the flow store
MAX_FLOW_EVENTS_PER_IP = 200
# Max IPs to track simultaneously
MAX_IPS = 2000
# Session timeout — no request for this long = new session
SESSION_TIMEOUT_SECONDS = 300  # 5 minutes


class FlowEvent:
    """A single event in an IP's request flow."""
    __slots__ = ("timestamp", "path", "method", "status", "user_agent")

    def __init__(
        self,
        timestamp:  datetime,
        path:       str,
        method:     str,
        status:     int,
        user_agent: str,
    ):
        self.timestamp  = timestamp
        self.path       = path[:512]
        self.method     = method
        self.status     = status
        self.user_agent = user_agent[:256]


class IPFlowState:
    """Request flow state for a single IP address."""

    def __init__(self, ip: str):
        self.ip:          str = ip
        self.events:      Deque[FlowEvent] = deque(maxlen=MAX_FLOW_EVENTS_PER_IP)
        self.session_start: Optional[datetime] = None
        self.session_count: int = 0
        self.last_seen:   Optional[datetime] = None

    def add_event(self, event: FlowEvent):
        now = event.timestamp

        # Detect new session
        if self.last_seen is None or (now - self.last_seen).total_seconds() > SESSION_TIMEOUT_SECONDS:
            self.session_start = now
            self.session_count += 1

        self.last_seen = now
        self.events.append(event)

    def get_recent_sequence(self, window_seconds: int = 120) -> List[FlowEvent]:
        """Return events within the last N seconds."""
        if not self.events:
            return []
        cutoff = self.events[-1].timestamp - timedelta(seconds=window_seconds)
        return [e for e in self.events if e.timestamp >= cutoff]

    def get_session_sequence(self) -> List[FlowEvent]:
        """Return all events in the current session."""
        if not self.session_start:
            return list(self.events)
        return [e for e in self.events if e.timestamp >= self.session_start]


class FlowSessionStore:
    """
    Thread-safe store for per-IP request flow states.
    Tracks sequences of requests to enable workflow-level detection.
    """

    def __init__(self):
        self._states: Dict[str, IPFlowState] = {}
        self._lock = Lock()

    def add_event(
        self,
        remote_ip:  str,
        timestamp:  datetime,
        path:       str,
        method:     str,
        status:     int,
        user_agent: str = "",
    ):
        """Record a request event for an IP."""
        with self._lock:
            # Enforce IP cap
            if remote_ip not in self._states and len(self._states) >= MAX_IPS:
                # Evict the IP that was least recently seen
                lru = min(self._states.values(), key=lambda s: s.last_seen or datetime.min)
                del self._states[lru.ip]

            if remote_ip not in self._states:
                self._states[remote_ip] = IPFlowState(remote_ip)

            event = FlowEvent(timestamp, path, method, status, user_agent)
            self._states[remote_ip].add_event(event)

    def get_state(self, ip: str) -> Optional[IPFlowState]:
        with self._lock:
            return self._states.get(ip)

    def get_sequence(self, ip: str, window_seconds: int = 120) -> List[FlowEvent]:
        with self._lock:
            state = self._states.get(ip)
            if state is None:
                return []
            return state.get_recent_sequence(window_seconds)

    def evict_stale(self, max_idle_seconds: int = 1800):
        """Remove IPs inactive for more than max_idle_seconds."""
        now = datetime.now()
        with self._lock:
            stale = [
                ip for ip, state in self._states.items()
                if state.last_seen and (now - state.last_seen).total_seconds() > max_idle_seconds
            ]
            for ip in stale:
                del self._states[ip]


# Module-level singleton
_flow_store: Optional[FlowSessionStore] = None


def get_flow_store() -> FlowSessionStore:
    global _flow_store
    if _flow_store is None:
        _flow_store = FlowSessionStore()
    return _flow_store
