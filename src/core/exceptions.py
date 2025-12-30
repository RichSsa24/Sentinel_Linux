"""
Custom exception classes for Linux Security Monitor.

Provides a hierarchy of exceptions for specific error conditions,
enabling precise error handling and meaningful error messages.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class SecurityMonitorError(Exception):
    """
    Base exception for all security monitor errors.

    All custom exceptions inherit from this class, allowing
    callers to catch all monitor-specific exceptions.

    Attributes:
        message: Human-readable error description.
        details: Additional context about the error.
        error_code: Optional error code for categorization.
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> None:
        """
        Initialize the exception.

        Args:
            message: Human-readable error description.
            details: Additional context about the error.
            error_code: Optional error code for categorization.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.error_code = error_code

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for serialization.

        Returns:
            Dictionary representation of the exception.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
            "error_code": self.error_code,
        }


class ConfigurationError(SecurityMonitorError):
    """
    Exception raised for configuration-related errors.

    Raised when:
    - Configuration file is missing or malformed
    - Required configuration values are missing
    - Configuration values fail validation
    """

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_file: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize configuration error.

        Args:
            message: Error description.
            config_key: The configuration key that caused the error.
            config_file: Path to the configuration file.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if config_key:
            details["config_key"] = config_key
        if config_file:
            details["config_file"] = config_file

        super().__init__(message, details=details, error_code="CONFIG_ERROR", **kwargs)


class MonitorInitError(SecurityMonitorError):
    """
    Exception raised when a monitor fails to initialize.

    Raised when:
    - Required system resources are unavailable
    - Monitor dependencies are missing
    - Initial data collection fails
    """

    def __init__(
        self,
        message: str,
        monitor_name: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize monitor initialization error.

        Args:
            message: Error description.
            monitor_name: Name of the monitor that failed.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if monitor_name:
            details["monitor_name"] = monitor_name

        super().__init__(message, details=details, error_code="MONITOR_INIT", **kwargs)


class CollectionError(SecurityMonitorError):
    """
    Exception raised when data collection fails.

    Raised when:
    - Log files cannot be read
    - System data is unavailable
    - Collection times out
    """

    def __init__(
        self,
        message: str,
        source: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize collection error.

        Args:
            message: Error description.
            source: The data source that failed.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if source:
            details["source"] = source

        super().__init__(message, details=details, error_code="COLLECTION_ERROR", **kwargs)


class AnalysisError(SecurityMonitorError):
    """
    Exception raised when event analysis fails.

    Raised when:
    - Analysis rules fail to load
    - Event processing encounters an error
    - Correlation fails
    """

    def __init__(
        self,
        message: str,
        analyzer: Optional[str] = None,
        event_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize analysis error.

        Args:
            message: Error description.
            analyzer: Name of the analyzer that failed.
            event_id: ID of the event being analyzed.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if analyzer:
            details["analyzer"] = analyzer
        if event_id:
            details["event_id"] = event_id

        super().__init__(message, details=details, error_code="ANALYSIS_ERROR", **kwargs)


class ReporterError(SecurityMonitorError):
    """
    Exception raised when alert delivery fails.

    Raised when:
    - Reporter destination is unreachable
    - Authentication fails
    - Message formatting fails
    """

    def __init__(
        self,
        message: str,
        reporter: Optional[str] = None,
        destination: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize reporter error.

        Args:
            message: Error description.
            reporter: Name of the reporter that failed.
            destination: Target destination that was unreachable.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if reporter:
            details["reporter"] = reporter
        if destination:
            details["destination"] = destination

        super().__init__(message, details=details, error_code="REPORTER_ERROR", **kwargs)


class ValidationError(SecurityMonitorError):
    """
    Exception raised when input validation fails.

    Raised when:
    - User input fails validation
    - Data format is incorrect
    - Security constraints are violated
    """

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        constraint: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize validation error.

        Args:
            message: Error description.
            field: Name of the field that failed validation.
            value: The invalid value (sanitized).
            constraint: The constraint that was violated.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if field:
            details["field"] = field
        if value is not None:
            # Sanitize value for logging
            details["value_type"] = type(value).__name__
        if constraint:
            details["constraint"] = constraint

        super().__init__(message, details=details, error_code="VALIDATION_ERROR", **kwargs)


class PermissionDeniedError(SecurityMonitorError):
    """
    Exception raised when operation lacks required permissions.

    Raised when:
    - File access is denied
    - System call requires elevated privileges
    - Capability is missing
    """

    def __init__(
        self,
        message: str,
        resource: Optional[str] = None,
        required_permission: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize permission denied error.

        Args:
            message: Error description.
            resource: The resource that was inaccessible.
            required_permission: The permission that was required.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if resource:
            details["resource"] = resource
        if required_permission:
            details["required_permission"] = required_permission

        super().__init__(message, details=details, error_code="PERMISSION_DENIED", **kwargs)


class ProcessNotFoundError(SecurityMonitorError):
    """
    Exception raised when a process cannot be found.

    Raised when:
    - Process has terminated
    - PID does not exist
    - Process information is unavailable
    """

    def __init__(
        self,
        message: str,
        pid: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize process not found error.

        Args:
            message: Error description.
            pid: Process ID that was not found.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if pid is not None:
            details["pid"] = pid

        super().__init__(message, details=details, error_code="PROCESS_NOT_FOUND", **kwargs)


class RateLimitError(SecurityMonitorError):
    """
    Exception raised when rate limit is exceeded.

    Raised when:
    - Alert rate limit is exceeded
    - API rate limit is hit
    - Collection rate is too high
    """

    def __init__(
        self,
        message: str,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize rate limit error.

        Args:
            message: Error description.
            limit: The rate limit that was exceeded.
            window: The time window in seconds.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if limit is not None:
            details["limit"] = limit
        if window is not None:
            details["window_seconds"] = window

        super().__init__(message, details=details, error_code="RATE_LIMIT", **kwargs)


class IOCMatchError(SecurityMonitorError):
    """
    Exception raised when IOC matching fails.

    Raised when:
    - IOC database is corrupted
    - IOC format is invalid
    - Matching operation fails
    """

    def __init__(
        self,
        message: str,
        ioc_type: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize IOC match error.

        Args:
            message: Error description.
            ioc_type: Type of IOC that caused the error.
            **kwargs: Additional arguments passed to parent.
        """
        details = kwargs.pop("details", {})
        if ioc_type:
            details["ioc_type"] = ioc_type

        super().__init__(message, details=details, error_code="IOC_MATCH_ERROR", **kwargs)



