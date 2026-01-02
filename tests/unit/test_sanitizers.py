"""Tests for data sanitization utilities."""

from __future__ import annotations

from src.utils.sanitizers import (
    sanitize_log_message,
    sanitize_path,
    sanitize_command,
    sanitize_dict,
    escape_shell,
    truncate,
)


class TestSanitizeLogMessage:
    """Tests for log message sanitization."""

    def test_removes_passwords(self) -> None:
        """Password values should be redacted."""
        msg = "User login with password=secret123"
        sanitized = sanitize_log_message(msg)
        assert "secret123" not in sanitized
        assert "password=***" in sanitized

    def test_removes_tokens(self) -> None:
        """Token values should be redacted."""
        msg = "API call with token=abc123xyz"
        sanitized = sanitize_log_message(msg)
        assert "abc123xyz" not in sanitized

    def test_removes_control_chars(self) -> None:
        """Control characters should be removed."""
        msg = "Normal text\x00with\x01control\x02chars"
        sanitized = sanitize_log_message(msg)
        assert "\x00" not in sanitized
        assert "\x01" not in sanitized

    def test_truncates_long_messages(self) -> None:
        """Very long messages should be truncated."""
        msg = "x" * 20000
        sanitized = sanitize_log_message(msg)
        assert len(sanitized) <= 10100  # Max + truncation message


class TestSanitizePath:
    """Tests for path sanitization."""

    def test_removes_null_bytes(self) -> None:
        """Null bytes should be removed."""
        path = "/etc/passwd\x00"
        sanitized = sanitize_path(path)
        assert "\x00" not in sanitized

    def test_normalizes_path(self) -> None:
        """Paths should be normalized."""
        path = "/etc//passwd"
        sanitized = sanitize_path(path)
        assert "//" not in sanitized


class TestSanitizeCommand:
    """Tests for command sanitization."""

    def test_redacts_password_args(self) -> None:
        """Password arguments should be redacted."""
        cmd = "mysql -u root -psecret123"
        sanitized = sanitize_command(cmd)
        assert "secret123" not in sanitized

    def test_preserves_safe_commands(self) -> None:
        """Safe commands should be preserved."""
        cmd = "ls -la /tmp"
        sanitized = sanitize_command(cmd)
        assert sanitized == cmd


class TestSanitizeDict:
    """Tests for dictionary sanitization."""

    def test_redacts_sensitive_keys(self) -> None:
        """Sensitive keys should be redacted."""
        data = {
            "username": "testuser",
            "password": "secret123",
            "api_key": "abc123",
        }
        sanitized = sanitize_dict(data)

        assert sanitized["username"] == "testuser"
        assert sanitized["password"] == "***REDACTED***"
        assert sanitized["api_key"] == "***REDACTED***"

    def test_handles_nested_dicts(self) -> None:
        """Nested dictionaries should be sanitized."""
        data = {
            "user": {
                "name": "test",
                "password": "secret",
            }
        }
        sanitized = sanitize_dict(data)
        assert sanitized["user"]["password"] == "***REDACTED***"


class TestEscapeShell:
    """Tests for shell escaping."""

    def test_safe_strings_unchanged(self) -> None:
        """Safe strings should not be modified."""
        assert escape_shell("simple") == "simple"
        assert escape_shell("/path/to/file") == "/path/to/file"

    def test_special_chars_escaped(self) -> None:
        """Special characters should be escaped."""
        result = escape_shell("test; rm -rf /")
        assert "'" in result


class TestTruncate:
    """Tests for text truncation."""

    def test_short_text_unchanged(self) -> None:
        """Short text should not be modified."""
        text = "short"
        assert truncate(text, 100) == text

    def test_long_text_truncated(self) -> None:
        """Long text should be truncated."""
        text = "x" * 100
        result = truncate(text, 50)
        assert len(result) == 50
        assert result.endswith("...")


