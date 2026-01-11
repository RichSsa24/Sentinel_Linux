"""Tests for exception handling."""

from __future__ import annotations

import pytest

from src.core.exceptions import (
    AnalysisError,
    CollectionError,
    ConfigurationError,
    MonitorInitError,
    PermissionDeniedError,
    ReporterError,
    SecurityMonitorError,
    ValidationError,
)


class TestSecurityMonitorError:
    """Tests for base SecurityMonitorError class."""

    def test_base_exception_creation(self) -> None:
        """Should create base exception."""
        error = SecurityMonitorError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.details == {}
        assert error.error_code is None

    def test_exception_with_details(self) -> None:
        """Should create exception with details."""
        error = SecurityMonitorError(
            "Test error",
            details={"key": "value"},
            error_code="TEST_ERROR",
        )
        assert error.details == {"key": "value"}
        assert error.error_code == "TEST_ERROR"
        assert "[TEST_ERROR]" in str(error)

    def test_exception_to_dict(self) -> None:
        """Should convert exception to dictionary."""
        error = SecurityMonitorError(
            "Test error",
            details={"key": "value"},
            error_code="TEST_ERROR",
        )
        error_dict = error.to_dict()

        assert error_dict["error_type"] == "SecurityMonitorError"
        assert error_dict["message"] == "Test error"
        assert error_dict["details"] == {"key": "value"}
        assert error_dict["error_code"] == "TEST_ERROR"


class TestConfigurationError:
    """Tests for ConfigurationError."""

    def test_config_error_creation(self) -> None:
        """Should create configuration error."""
        error = ConfigurationError(
            "Invalid config",
            config_key="test_key",
            config_file="/path/to/config.yaml",
        )
        assert error.error_code == "CONFIG_ERROR"
        assert error.details["config_key"] == "test_key"
        assert error.details["config_file"] == "/path/to/config.yaml"


class TestMonitorInitError:
    """Tests for MonitorInitError."""

    def test_monitor_init_error(self) -> None:
        """Should create monitor init error."""
        error = MonitorInitError("Failed to init", monitor_name="test_monitor")
        assert error.error_code == "MONITOR_INIT"
        assert error.details["monitor_name"] == "test_monitor"


class TestCollectionError:
    """Tests for CollectionError."""

    def test_collection_error(self) -> None:
        """Should create collection error."""
        error = CollectionError("Collection failed", source="/var/log/auth.log")
        assert error.error_code == "COLLECTION_ERROR"
        assert error.details["source"] == "/var/log/auth.log"


class TestAnalysisError:
    """Tests for AnalysisError."""

    def test_analysis_error(self) -> None:
        """Should create analysis error."""
        error = AnalysisError(
            "Analysis failed",
            analyzer="threat_analyzer",
            event_id="event-001",
        )
        assert error.error_code == "ANALYSIS_ERROR"
        assert error.details["analyzer"] == "threat_analyzer"
        assert error.details["event_id"] == "event-001"


class TestReporterError:
    """Tests for ReporterError."""

    def test_reporter_error(self) -> None:
        """Should create reporter error."""
        error = ReporterError(
            "Reporter failed",
            reporter="webhook_reporter",
            destination="https://example.com/webhook",
        )
        assert error.error_code == "REPORTER_ERROR"
        assert error.details["reporter"] == "webhook_reporter"
        assert error.details["destination"] == "https://example.com/webhook"


class TestValidationError:
    """Tests for ValidationError."""

    def test_validation_error(self) -> None:
        """Should create validation error."""
        error = ValidationError(
            "Validation failed",
            field="path",
            value="/etc/passwd",
            constraint="must be absolute path",
        )
        assert error.error_code == "VALIDATION_ERROR"
        assert error.details["field"] == "path"
        assert error.details["constraint"] == "must be absolute path"
        # Value should be sanitized (type only, not actual value)
        assert "value_type" in error.details


class TestPermissionDeniedError:
    """Tests for PermissionDeniedError."""

    def test_permission_denied_error(self) -> None:
        """Should create permission denied error."""
        error = PermissionDeniedError(
            "Permission denied",
            resource="/etc/shadow",
            required_permission="read",
        )
        assert error.error_code == "PERMISSION_DENIED"
        assert error.details["resource"] == "/etc/shadow"
        assert error.details["required_permission"] == "read"


class TestExceptionHierarchy:
    """Tests for exception hierarchy."""

    def test_all_exceptions_inherit_from_base(self) -> None:
        """All exceptions should inherit from SecurityMonitorError."""
        exceptions = [
            ConfigurationError("test"),
            MonitorInitError("test"),
            CollectionError("test"),
            AnalysisError("test"),
            ReporterError("test"),
            ValidationError("test"),
            PermissionDeniedError("test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, SecurityMonitorError)

    def test_exception_catching(self) -> None:
        """Should be able to catch all exceptions with base class."""
        try:
            raise ConfigurationError("Test error")
        except SecurityMonitorError as e:
            assert isinstance(e, ConfigurationError)
            assert str(e) == "Test error"

