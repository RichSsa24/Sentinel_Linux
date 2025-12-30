"""
Abstract base class for security monitors.

Provides the foundation for all monitoring components with
a consistent interface for lifecycle management and data collection.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from src.config.logging_config import get_logger
from src.core.exceptions import MonitorInitError, CollectionError


logger = get_logger(__name__)


class Severity(Enum):
    """Severity levels for security events."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name

    def __ge__(self, other: "Severity") -> bool:
        return self.value >= other.value

    def __gt__(self, other: "Severity") -> bool:
        return self.value > other.value

    def __le__(self, other: "Severity") -> bool:
        return self.value <= other.value

    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value


class EventType(Enum):
    """Types of security events."""

    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_PRIVILEGE_ESCALATION = "user_privilege_escalation"
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    PROCESS_START = "process_start"
    PROCESS_SUSPICIOUS = "process_suspicious"
    NETWORK_CONNECTION = "network_connection"
    NETWORK_LISTENER = "network_listener"
    FILE_MODIFIED = "file_modified"
    FILE_CREATED = "file_created"
    FILE_DELETED = "file_deleted"
    FILE_PERMISSION_CHANGED = "file_permission_changed"
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    SERVICE_NEW = "service_new"
    LOG_PATTERN_MATCH = "log_pattern_match"
    ANOMALY_DETECTED = "anomaly_detected"
    IOC_MATCH = "ioc_match"
    BRUTE_FORCE = "brute_force"


@dataclass
class EventSource:
    """Source information for an event."""

    monitor: str
    host: str
    ip: Optional[str] = None


@dataclass
class EventSubject:
    """Subject (actor) of an event."""

    user: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    uid: Optional[int] = None


@dataclass
class EventObject:
    """Object (target) of an event."""

    type: str
    path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    """
    Represents a security event detected by a monitor.

    This is the base event structure used throughout the system
    for passing security-relevant information between components.
    """

    event_id: str
    timestamp: datetime
    event_type: EventType
    severity: Severity
    source: EventSource
    description: str
    raw: str = ""
    subject: Optional[EventSubject] = None
    object: Optional[EventObject] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "severity": self.severity.name,
            "source": {
                "monitor": self.source.monitor,
                "host": self.source.host,
                "ip": self.source.ip,
            },
            "description": self.description,
            "raw": self.raw,
            "subject": {
                "user": self.subject.user,
                "process": self.subject.process,
                "pid": self.subject.pid,
                "uid": self.subject.uid,
            } if self.subject else None,
            "object": {
                "type": self.object.type,
                "path": self.object.path,
                "details": self.object.details,
            } if self.object else None,
            "metadata": self.metadata,
        }


@dataclass
class MonitorStatus:
    """Status information for a monitor."""

    name: str
    running: bool
    last_collection: Optional[datetime] = None
    events_collected: int = 0
    errors_count: int = 0
    last_error: Optional[str] = None
    uptime_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert status to dictionary."""
        return {
            "name": self.name,
            "running": self.running,
            "last_collection": self.last_collection.isoformat() if self.last_collection else None,
            "events_collected": self.events_collected,
            "errors_count": self.errors_count,
            "last_error": self.last_error,
            "uptime_seconds": self.uptime_seconds,
        }


class BaseMonitor(ABC):
    """
    Abstract base class for all security monitors.

    Provides a consistent interface for:
    - Lifecycle management (start/stop)
    - Data collection
    - Status reporting
    - Error handling

    Subclasses must implement the abstract methods to provide
    specific monitoring functionality.
    """

    def __init__(
        self,
        name: str,
        config: Dict[str, Any],
        hostname: Optional[str] = None,
    ) -> None:
        """
        Initialize the base monitor.

        Args:
            name: Unique identifier for this monitor.
            config: Monitor-specific configuration.
            hostname: Hostname for event sources (auto-detected if None).
        """
        self.name = name
        self.config = config
        self.hostname = hostname or self._get_hostname()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._start_time: Optional[datetime] = None
        self._events_collected = 0
        self._errors_count = 0
        self._last_error: Optional[str] = None
        self._last_collection: Optional[datetime] = None
        self._lock = threading.Lock()

        self.poll_interval = config.get("poll_interval", 60)
        self.enabled = config.get("enabled", True)

        logger.debug(f"Initialized {name} monitor")

    def _get_hostname(self) -> str:
        """Get system hostname."""
        import socket
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"

    @abstractmethod
    def _initialize(self) -> None:
        """
        Initialize monitor-specific resources.

        Called during start() before the collection loop begins.
        Override to set up data sources, connections, etc.

        Raises:
            MonitorInitError: If initialization fails.
        """
        pass

    @abstractmethod
    def _collect(self) -> List[Event]:
        """
        Perform a single collection cycle.

        Override to implement the actual data collection logic.

        Returns:
            List of events collected in this cycle.

        Raises:
            CollectionError: If collection fails.
        """
        pass

    @abstractmethod
    def _cleanup(self) -> None:
        """
        Clean up monitor resources.

        Called during stop() after the collection loop ends.
        Override to close connections, release resources, etc.
        """
        pass

    def start(self) -> None:
        """
        Start the monitor.

        Initializes resources and starts the collection thread.

        Raises:
            MonitorInitError: If initialization fails.
        """
        if not self.enabled:
            logger.info(f"{self.name} monitor is disabled, not starting")
            return

        if self._running:
            logger.warning(f"{self.name} monitor is already running")
            return

        logger.info(f"Starting {self.name} monitor")

        try:
            self._initialize()
        except Exception as e:
            raise MonitorInitError(
                f"Failed to initialize {self.name} monitor: {e}",
                monitor_name=self.name,
            )

        self._running = True
        self._start_time = datetime.now()
        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._collection_loop,
            name=f"{self.name}-collector",
            daemon=True,
        )
        self._thread.start()

        logger.info(f"{self.name} monitor started")

    def stop(self) -> None:
        """
        Stop the monitor.

        Signals the collection thread to stop and waits for cleanup.
        """
        if not self._running:
            return

        logger.info(f"Stopping {self.name} monitor")

        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

        self._running = False

        try:
            self._cleanup()
        except Exception as e:
            logger.error(f"Error during {self.name} cleanup: {e}")

        logger.info(f"{self.name} monitor stopped")

    def _collection_loop(self) -> None:
        """Main collection loop running in a separate thread."""
        while not self._stop_event.is_set():
            try:
                events = self._collect()

                with self._lock:
                    self._last_collection = datetime.now()
                    self._events_collected += len(events)

                for event in events:
                    self._handle_event(event)

            except CollectionError as e:
                self._record_error(str(e))
                logger.warning(f"{self.name} collection error: {e}")

            except Exception as e:
                self._record_error(str(e))
                logger.error(f"{self.name} unexpected error: {e}", exc_info=True)

            # Wait for next collection cycle or stop signal
            self._stop_event.wait(timeout=self.poll_interval)

    def _record_error(self, error: str) -> None:
        """Record an error occurrence."""
        with self._lock:
            self._errors_count += 1
            self._last_error = error

    def _handle_event(self, event: Event) -> None:
        """
        Handle a collected event.

        Override to customize event handling. Default implementation
        logs the event.

        Args:
            event: The collected event.
        """
        logger.debug(
            f"{self.name} collected event: {event.event_type.value} - {event.description}"
        )

    def collect(self) -> List[Event]:
        """
        Perform a single collection cycle (blocking).

        This can be called directly for one-shot collection
        without starting the background thread.

        Returns:
            List of events collected.

        Raises:
            CollectionError: If collection fails.
        """
        if not self.enabled:
            return []

        return self._collect()

    def get_status(self) -> MonitorStatus:
        """
        Get current monitor status.

        Returns:
            MonitorStatus object with current state.
        """
        with self._lock:
            uptime = 0.0
            if self._start_time and self._running:
                uptime = (datetime.now() - self._start_time).total_seconds()

            return MonitorStatus(
                name=self.name,
                running=self._running,
                last_collection=self._last_collection,
                events_collected=self._events_collected,
                errors_count=self._errors_count,
                last_error=self._last_error,
                uptime_seconds=uptime,
            )

    def create_event(
        self,
        event_type: EventType,
        severity: Severity,
        description: str,
        raw: str = "",
        subject: Optional[EventSubject] = None,
        obj: Optional[EventObject] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Event:
        """
        Create an event with standard source information.

        Args:
            event_type: Type of the event.
            severity: Severity level.
            description: Human-readable description.
            raw: Raw data that triggered the event.
            subject: Event subject (actor).
            obj: Event object (target).
            metadata: Additional metadata.

        Returns:
            Constructed Event object.
        """
        import uuid

        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            source=EventSource(
                monitor=self.name,
                host=self.hostname,
                ip=None,
            ),
            description=description,
            raw=raw,
            subject=subject,
            object=obj,
            metadata=metadata or {},
        )

    def __enter__(self) -> "BaseMonitor":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.stop()



