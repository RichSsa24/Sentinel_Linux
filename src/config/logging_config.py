"""
Logging configuration module.

Provides centralized logging setup with support for:
- Console output with colors
- File logging with rotation
- JSON structured logging
- Syslog integration
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from pythonjsonlogger import jsonlogger


class ColoredFormatter(logging.Formatter):
    """
    Colored log formatter for console output.

    Adds ANSI color codes based on log level.
    """

    COLORS = {
        "DEBUG": "\033[36m",      # Cyan
        "INFO": "\033[32m",       # Green
        "WARNING": "\033[33m",    # Yellow
        "ERROR": "\033[31m",      # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        use_colors: bool = True,
    ) -> None:
        """
        Initialize the colored formatter.

        Args:
            fmt: Log format string.
            datefmt: Date format string.
            use_colors: Whether to use color codes.
        """
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with optional colors.

        Args:
            record: Log record to format.

        Returns:
            Formatted log string.
        """
        if self.use_colors and record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
            )
        return super().format(record)


class SecurityJsonFormatter(jsonlogger.JsonFormatter):
    """
    JSON formatter with security-relevant fields.

    Adds standard fields for SIEM integration.
    """

    def add_fields(
        self,
        log_record: Dict[str, Any],
        record: logging.LogRecord,
        message_dict: Dict[str, Any],
    ) -> None:
        """
        Add custom fields to the JSON log record.

        Args:
            log_record: Dictionary to populate.
            record: Original log record.
            message_dict: Message dictionary.
        """
        super().add_fields(log_record, record, message_dict)

        log_record["timestamp"] = self.formatTime(record)
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        log_record["module"] = record.module
        log_record["function"] = record.funcName
        log_record["line"] = record.lineno

        if hasattr(record, "event_type"):
            log_record["event_type"] = record.event_type
        if hasattr(record, "severity"):
            log_record["severity"] = record.severity
        if hasattr(record, "source_ip"):
            log_record["source_ip"] = record.source_ip
        if hasattr(record, "user"):
            log_record["user"] = record.user


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
    use_colors: bool = True,
    syslog_host: Optional[str] = None,
    syslog_port: int = 514,
) -> logging.Logger:
    """
    Set up logging configuration.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to log file (None for console only).
        json_format: Use JSON format for logs.
        use_colors: Use colored console output.
        syslog_host: Syslog server hostname (None to disable).
        syslog_port: Syslog server port.

    Returns:
        Configured root logger.
    """
    # Get numeric level
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Create root logger
    root_logger = logging.getLogger("linux_security_monitor")
    root_logger.setLevel(numeric_level)

    # Clear existing handlers
    root_logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    if json_format:
        console_formatter: Union[SecurityJsonFormatter, ColoredFormatter] = SecurityJsonFormatter(
            "%(timestamp)s %(level)s %(name)s %(message)s"
        )
    else:
        console_formatter = ColoredFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            use_colors=use_colors and sys.stdout.isatty(),
        )

    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(numeric_level)

            if json_format:
                file_formatter: Union[SecurityJsonFormatter, logging.Formatter] = SecurityJsonFormatter(
                    "%(timestamp)s %(level)s %(name)s %(message)s"
                )
            else:
                file_formatter = logging.Formatter(
                    fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )

            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
        except PermissionError:
            # Fallback to user's home directory or temp
            fallback_paths = [
                Path.home() / ".local" / "log" / "Sentinel_Linux" / "monitor.log",
                Path("/tmp") / "Sentinel_Linux" / "monitor.log",
            ]
            for fallback in fallback_paths:
                try:
                    fallback.parent.mkdir(parents=True, exist_ok=True)
                    file_handler = logging.handlers.RotatingFileHandler(
                        str(fallback),
                        maxBytes=10 * 1024 * 1024,
                        backupCount=5,
                        encoding="utf-8",
                    )
                    file_handler.setLevel(numeric_level)
                    file_formatter: logging.Formatter = logging.Formatter(
                        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S",
                    )
                    file_handler.setFormatter(file_formatter)
                    root_logger.addHandler(file_handler)
                    root_logger.warning(
                        f"Could not write to {log_file}, using fallback: {fallback}"
                    )
                    break
                except (PermissionError, OSError):
                    continue
        except OSError as e:
            root_logger.warning(f"Failed to configure file handler: {e}")

    # Syslog handler
    if syslog_host:
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=(syslog_host, syslog_port),
                facility=logging.handlers.SysLogHandler.LOG_LOCAL0,
            )
            syslog_handler.setLevel(numeric_level)

            syslog_formatter = logging.Formatter(
                fmt="Sentinel_Linux[%(process)d]: %(levelname)s %(message)s"
            )
            syslog_handler.setFormatter(syslog_formatter)
            root_logger.addHandler(syslog_handler)
        except Exception as e:
            root_logger.warning(f"Failed to configure syslog handler: {e}")

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (typically module name).

    Returns:
        Logger instance.
    """
    return logging.getLogger(f"linux_security_monitor.{name}")


class LoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter with security context.

    Allows adding security-relevant context to all log messages.
    """

    def process(
        self, msg: str, kwargs: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Process log message with extra context.

        Args:
            msg: Log message.
            kwargs: Additional keyword arguments.

        Returns:
            Processed message and kwargs.
        """
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra
        return msg, kwargs


def get_security_logger(
    name: str,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    user: Optional[str] = None,
) -> LoggerAdapter:
    """
    Get a security-context logger.

    Args:
        name: Logger name.
        event_type: Type of security event.
        source_ip: Source IP address.
        user: Associated username.

    Returns:
        Logger adapter with security context.
    """
    logger = get_logger(name)
    extra: Dict[str, Any] = {}

    if event_type:
        extra["event_type"] = event_type
    if source_ip:
        extra["source_ip"] = source_ip
    if user:
        extra["user"] = user

    return LoggerAdapter(logger, extra)


