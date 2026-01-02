"""
Data sanitization utilities.

Provides functions to sanitize data for safe logging,
display, and storage.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional


# Patterns for sensitive data
SENSITIVE_PATTERNS = [
    (re.compile(r"password[=:]\s*\S+", re.IGNORECASE), "password=***"),
    (re.compile(r"passwd[=:]\s*\S+", re.IGNORECASE), "passwd=***"),
    (re.compile(r"secret[=:]\s*\S+", re.IGNORECASE), "secret=***"),
    (re.compile(r"token[=:]\s*\S+", re.IGNORECASE), "token=***"),
    (re.compile(r"api_key[=:]\s*\S+", re.IGNORECASE), "api_key=***"),
    (re.compile(r"apikey[=:]\s*\S+", re.IGNORECASE), "apikey=***"),
    (re.compile(r"authorization:\s*\S+", re.IGNORECASE), "authorization: ***"),
    (re.compile(r"bearer\s+\S+", re.IGNORECASE), "bearer ***"),
    (re.compile(r"private_key[=:]\s*\S+", re.IGNORECASE), "private_key=***"),
]

# Control characters to remove
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_log_message(message: str) -> str:
    """
    Remove sensitive data from log messages.

    Args:
        message: Log message to sanitize.

    Returns:
        Sanitized message.
    """
    if not message:
        return ""

    sanitized = message

    # Remove sensitive data
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    # Remove control characters
    sanitized = CONTROL_CHARS.sub("", sanitized)

    # Truncate very long messages
    max_length = 10000
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "...[truncated]"

    return sanitized


def sanitize_path(path: str) -> str:
    """
    Canonicalize and validate file path.

    Args:
        path: File path to sanitize.

    Returns:
        Sanitized canonical path.
    """
    if not path:
        return ""

    # Remove null bytes
    path = path.replace("\x00", "")

    # Normalize path
    path = os.path.normpath(path)

    # Resolve to absolute path
    try:
        path = os.path.realpath(path)
    except (OSError, ValueError):
        pass

    return path


def sanitize_command(command: str) -> str:
    """
    Sanitize command for safe logging.

    Args:
        command: Command string to sanitize.

    Returns:
        Sanitized command.
    """
    if not command:
        return ""

    sanitized = command

    # Redact common sensitive arguments
    sensitive_args = [
        (re.compile(r"(-p|--password)[=\s]+\S+"), r"\1=***"),
        (re.compile(r"(-P|--pass)[=\s]+\S+"), r"\1=***"),
        (re.compile(r"(-k|--key)[=\s]+\S+"), r"\1=***"),
        (re.compile(r"(-t|--token)[=\s]+\S+"), r"\1=***"),
        (re.compile(r"mysql\s+.*-p\S+"), "mysql ... -p***"),
    ]

    for pattern, replacement in sensitive_args:
        sanitized = pattern.sub(replacement, sanitized)

    # Remove control characters
    sanitized = CONTROL_CHARS.sub("", sanitized)

    return sanitized


def sanitize_dict(
    data: Dict[str, Any], sensitive_keys: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Sanitize dictionary by redacting sensitive keys.

    Args:
        data: Dictionary to sanitize.
        sensitive_keys: Additional keys to redact.

    Returns:
        Sanitized dictionary.
    """
    default_sensitive = {
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "private_key", "access_token", "refresh_token", "auth", "credentials",
    }

    if sensitive_keys:
        default_sensitive.update(k.lower() for k in sensitive_keys)

    def sanitize_value(key: str, value: Any) -> Any:
        if key.lower() in default_sensitive:
            return "***REDACTED***"

        if isinstance(value, dict):
            return sanitize_dict(value, sensitive_keys)

        if isinstance(value, list):
            return [
                sanitize_value(key, item) if isinstance(item, dict) else item
                for item in value
            ]

        if isinstance(value, str):
            return sanitize_log_message(value)

        return value

    return {k: sanitize_value(k, v) for k, v in data.items()}


def escape_shell(arg: str) -> str:
    """
    Escape argument for shell usage.

    Args:
        arg: Argument to escape.

    Returns:
        Escaped argument.
    """
    if not arg:
        return "''"

    # If only safe chars, return as-is
    if re.match(r"^[a-zA-Z0-9_./=-]+$", arg):
        return arg

    # Single-quote the argument
    return "'" + arg.replace("'", "'\"'\"'") + "'"


def truncate(text: str, max_length: int = 1000, suffix: str = "...") -> str:
    """
    Truncate text to maximum length.

    Args:
        text: Text to truncate.
        max_length: Maximum length.
        suffix: Suffix to add when truncated.

    Returns:
        Truncated text.
    """
    if not text or len(text) <= max_length:
        return text

    return text[:max_length - len(suffix)] + suffix


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text.

    Args:
        text: Text to normalize.

    Returns:
        Text with normalized whitespace.
    """
    if not text:
        return ""

    # Replace tabs and multiple spaces with single space
    text = re.sub(r"[\t ]+", " ", text)

    # Remove leading/trailing whitespace from lines
    lines = [line.strip() for line in text.split("\n")]

    return "\n".join(lines).strip()


