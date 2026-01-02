"""
Linux Security Monitor - Enterprise Security Monitoring Framework.

A comprehensive security monitoring solution for Linux systems,
providing real-time threat detection, anomaly analysis, and
security event correlation.
"""

__version__ = "1.0.0"
__author__ = "Ricardo Solís"
__license__ = "MIT"

from src.core.base_monitor import BaseMonitor
from src.core.event_handler import EventHandler
from src.core.alert_manager import AlertManager
from src.core.exceptions import (
    SecurityMonitorError,
    ConfigurationError,
    MonitorInitError,
    CollectionError,
)

__all__ = [
    "BaseMonitor",
    "EventHandler",
    "AlertManager",
    "SecurityMonitorError",
    "ConfigurationError",
    "MonitorInitError",
    "CollectionError",
]


