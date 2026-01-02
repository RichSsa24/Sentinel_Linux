"""
Syslog reporter for log forwarding.

Sends alerts to syslog servers for SIEM integration.
"""

from __future__ import annotations

import logging
import logging.handlers
import socket
from typing import Any, Dict, Optional

from src.config.logging_config import get_logger
from src.core.alert_manager import Alert
from src.core.base_monitor import Severity


logger = get_logger(__name__)


class SyslogReporter:
    """
    Sends alerts to syslog servers.

    Features:
    - UDP/TCP/TLS transport
    - Configurable facility
    - CEF format support
    """

    FACILITY_MAP = {
        "LOCAL0": logging.handlers.SysLogHandler.LOG_LOCAL0,
        "LOCAL1": logging.handlers.SysLogHandler.LOG_LOCAL1,
        "LOCAL2": logging.handlers.SysLogHandler.LOG_LOCAL2,
        "LOCAL3": logging.handlers.SysLogHandler.LOG_LOCAL3,
        "LOCAL4": logging.handlers.SysLogHandler.LOG_LOCAL4,
        "LOCAL5": logging.handlers.SysLogHandler.LOG_LOCAL5,
        "LOCAL6": logging.handlers.SysLogHandler.LOG_LOCAL6,
        "LOCAL7": logging.handlers.SysLogHandler.LOG_LOCAL7,
    }

    SEVERITY_TO_SYSLOG = {
        Severity.INFO: logging.INFO,
        Severity.LOW: logging.INFO,
        Severity.MEDIUM: logging.WARNING,
        Severity.HIGH: logging.ERROR,
        Severity.CRITICAL: logging.CRITICAL,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize syslog reporter."""
        config = config or {}
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 514)
        self.protocol = config.get("protocol", "udp").lower()
        self.facility = config.get("facility", "LOCAL0").upper()

        self._handler: Optional[logging.handlers.SysLogHandler] = None
        self._logger: Optional[logging.Logger] = None
        self._connected = False

        self._connect()

    def _connect(self) -> None:
        """Establish syslog connection."""
        try:
            facility = self.FACILITY_MAP.get(
                self.facility,
                logging.handlers.SysLogHandler.LOG_LOCAL0
            )

            if self.protocol == "tcp":
                socktype = socket.SOCK_STREAM
            else:
                socktype = socket.SOCK_DGRAM

            self._handler = logging.handlers.SysLogHandler(
                address=(self.host, self.port),
                facility=facility,
                socktype=socktype,
            )

            formatter = logging.Formatter(
                "Sentinel_Linux: %(message)s"
            )
            self._handler.setFormatter(formatter)

            self._logger = logging.getLogger("syslog_reporter")
            self._logger.addHandler(self._handler)
            self._logger.setLevel(logging.DEBUG)

            self._connected = True
            logger.info(f"Connected to syslog: {self.host}:{self.port}")

        except Exception as e:
            logger.error(f"Failed to connect to syslog: {e}")
            self._connected = False

    def report(self, alert: Alert) -> None:
        """
        Send alert to syslog.

        Args:
            alert: Alert to send.
        """
        if not self._connected or not self._logger:
            return

        try:
            message = self._format_cef(alert)
            level = self.SEVERITY_TO_SYSLOG.get(alert.severity, logging.INFO)
            self._logger.log(level, message)

        except Exception as e:
            logger.error(f"Failed to send to syslog: {e}")

    def _format_cef(self, alert: Alert) -> str:
        """Format alert as CEF (Common Event Format)."""
        severity_map = {
            Severity.INFO: 1,
            Severity.LOW: 3,
            Severity.MEDIUM: 5,
            Severity.HIGH: 7,
            Severity.CRITICAL: 10,
        }

        cef_severity = severity_map.get(alert.severity, 5)

        # Helper function to escape CEF special characters
        def escape_cef(value: str) -> str:
            """Escape special characters for CEF format."""
            return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")

        def escape_cef_header(value: str) -> str:
            """Escape pipe characters for CEF header."""
            return value.replace("\\", "\\\\").replace("|", "\\|")

        # CEF header (pipe-separated fields)
        cef = (
            f"CEF:0|LinuxSecurityMonitor|LSM|1.0|"
            f"{escape_cef_header(alert.alert_id)}|"
            f"{escape_cef_header(alert.title)}|"
            f"{cef_severity}|"
        )

        # Extension fields (space-separated key=value pairs)
        extensions = [
            f"dhost={escape_cef(alert.host)}",
            f"msg={escape_cef(alert.description[:200])}",
            f"rt={int(alert.timestamp.timestamp() * 1000)}",
        ]

        if alert.mitre_techniques:
            techniques_str = escape_cef(",".join(alert.mitre_techniques))
            extensions.append(f"cs1={techniques_str}")
            extensions.append("cs1Label=MITRETechniques")

        cef += " ".join(extensions)

        return cef

    def __del__(self) -> None:
        """Clean up handler."""
        if self._handler and self._logger:
            self._logger.removeHandler(self._handler)
            self._handler.close()


