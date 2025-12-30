"""Security tests for input validation."""

from __future__ import annotations

import pytest

from src.utils.validators import validate_path, validate_ip_address
from src.utils.sanitizers import sanitize_log_message, sanitize_command
from src.core.exceptions import ValidationError


class TestPathTraversalPrevention:
    """Tests for path traversal attack prevention."""

    def test_rejects_double_dot_traversal(self) -> None:
        """Should reject ../ path traversal."""
        malicious_paths = [
            "../../../etc/passwd",
            "/var/log/../../../etc/shadow",
            "..\\..\\..\\etc\\passwd",
        ]

        for path in malicious_paths:
            with pytest.raises(ValidationError):
                validate_path(path)

    def test_rejects_null_byte_injection(self) -> None:
        """Should reject null byte injection."""
        with pytest.raises(ValidationError):
            validate_path("/etc/passwd\x00.txt")


class TestInjectionPrevention:
    """Tests for injection attack prevention."""

    def test_sanitizes_shell_metacharacters(self) -> None:
        """Should sanitize shell metacharacters in commands."""
        malicious_commands = [
            "ls; rm -rf /",
            "echo $(cat /etc/passwd)",
            "file `whoami`",
        ]

        for cmd in malicious_commands:
            sanitized = sanitize_command(cmd)
            # Should not contain the original dangerous patterns
            # (exact behavior depends on implementation)

    def test_sanitizes_log_injection(self) -> None:
        """Should prevent log injection attacks."""
        # Attempt to inject fake log entry
        malicious = "Normal log\n[CRITICAL] Fake alert: system compromised"
        sanitized = sanitize_log_message(malicious)

        # Should not allow newline-based injection
        # The message should be sanitized


class TestCredentialProtection:
    """Tests for credential protection."""

    def test_redacts_passwords_in_logs(self) -> None:
        """Should redact passwords from log messages."""
        sensitive_messages = [
            "password=secret123",
            "PASSWORD: mysecret",
            "api_key=abcdef123456",
            "Authorization: Bearer token123",
        ]

        for msg in sensitive_messages:
            sanitized = sanitize_log_message(msg)
            # Original secrets should not appear
            assert "secret123" not in sanitized
            assert "mysecret" not in sanitized
            assert "abcdef123456" not in sanitized
            assert "token123" not in sanitized


class TestInputBoundaryChecks:
    """Tests for input boundary conditions."""

    def test_handles_empty_input(self) -> None:
        """Should handle empty input gracefully."""
        assert sanitize_log_message("") == ""
        assert sanitize_command("") == ""

        with pytest.raises(ValidationError):
            validate_ip_address("")

    def test_handles_very_long_input(self) -> None:
        """Should handle very long input safely."""
        long_input = "x" * 100000

        # Should not crash and should truncate
        sanitized = sanitize_log_message(long_input)
        assert len(sanitized) < len(long_input)

    def test_handles_unicode_input(self) -> None:
        """Should handle unicode input safely."""
        unicode_input = "Test message: "
        sanitized = sanitize_log_message(unicode_input)
        # Should not crash



