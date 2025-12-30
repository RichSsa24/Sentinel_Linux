"""
Core module containing base classes and fundamental components.

This module provides:
- BaseMonitor: Abstract base class for all monitors
- EventHandler: Central event processing
- AlertManager: Alert generation and delivery
- Custom exceptions
"""

from src.core.base_monitor import BaseMonitor, MonitorStatus
from src.core.event_handler import EventHandler, Event, ProcessedEvent
from src.core.alert_manager import AlertManager, Alert
from src.core.exceptions import (
    SecurityMonitorError,
    ConfigurationError,
    MonitorInitError,
    CollectionError,
    AnalysisError,
    ReporterError,
    ValidationError,
    PermissionDeniedError,
)

__all__ = [
    "BaseMonitor",
    "MonitorStatus",
    "EventHandler",
    "Event",
    "ProcessedEvent",
    "AlertManager",
    "Alert",
    "SecurityMonitorError",
    "ConfigurationError",
    "MonitorInitError",
    "CollectionError",
    "AnalysisError",
    "ReporterError",
    "ValidationError",
    "PermissionDeniedError",
]



