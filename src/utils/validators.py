"""
Input validation utilities.

Provides validation functions for various input types
to ensure security and data integrity.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.exceptions import ValidationError


def validate_ip_address(ip: str) -> bool:
    """
    Validate IPv4 or IPv6 address.

    Args:
        ip: IP address string.

    Returns:
        True if valid IP address.

    Raises:
        ValidationError: If IP is invalid.
    """
    if not ip or not isinstance(ip, str):
        raise ValidationError("IP address must be a non-empty string", field="ip")

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        raise ValidationError(f"Invalid IP address: {ip}", field="ip")


def validate_port(port: int) -> bool:
    """
    Validate port number.

    Args:
        port: Port number.

    Returns:
        True if valid port.

    Raises:
        ValidationError: If port is invalid.
    """
    if not isinstance(port, int):
        raise ValidationError("Port must be an integer", field="port")

    if port < 1 or port > 65535:
        raise ValidationError(
            f"Port must be between 1 and 65535, got {port}",
            field="port",
            constraint="1-65535",
        )

    return True


def validate_path(
    path: str,
    must_exist: bool = False,
    must_be_file: bool = False,
    must_be_dir: bool = False,
    allow_symlinks: bool = True,
) -> bool:
    """
    Validate file path.

    Args:
        path: File path to validate.
        must_exist: Path must exist.
        must_be_file: Path must be a file.
        must_be_dir: Path must be a directory.
        allow_symlinks: Allow symbolic links.

    Returns:
        True if valid path.

    Raises:
        ValidationError: If path is invalid.
    """
    if not path or not isinstance(path, str):
        raise ValidationError("Path must be a non-empty string", field="path")

    # Check for null bytes
    if "\x00" in path:
        raise ValidationError("Path contains null byte", field="path")

    # Check for path traversal attempts BEFORE normalization
    # Normalize resolves .. so we need to check the original path
    if ".." in path:
        # Check if .. appears in a way that could be used for traversal
        parts = path.split(os.sep)
        if ".." in parts:
            raise ValidationError("Path traversal not allowed", field="path")

    # Normalize path
    normalized = os.path.normpath(path)

    # Additional check: ensure normalized path doesn't escape base directory
    # Check if normalized path still contains .. components
    normalized_parts = normalized.split(os.sep)
    if ".." in normalized_parts:
        raise ValidationError("Path traversal not allowed", field="path")

    path_obj = Path(normalized)

    if must_exist and not path_obj.exists():
        raise ValidationError(f"Path does not exist: {path}", field="path")

    if not allow_symlinks and path_obj.is_symlink():
        raise ValidationError("Symbolic links not allowed", field="path")

    if must_be_file and path_obj.exists() and not path_obj.is_file():
        raise ValidationError(f"Path is not a file: {path}", field="path")

    if must_be_dir and path_obj.exists() and not path_obj.is_dir():
        raise ValidationError(f"Path is not a directory: {path}", field="path")

    return True


def validate_config(
    config: Dict[str, Any],
    schema: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate configuration dictionary.

    Args:
        config: Configuration to validate.
        schema: Optional schema for validation.

    Returns:
        Tuple of (is_valid, list of error messages).
    """
    errors: List[str] = []

    if not isinstance(config, dict):
        return False, ["Configuration must be a dictionary"]

    # Basic type checking
    if schema:
        errors.extend(_validate_against_schema(config, schema))

    return not errors, errors


def _validate_against_schema(
    config: Dict[str, Any],
    schema: Dict[str, Any],
    path: str = "",
) -> List[str]:
    """Validate config against schema recursively."""
    errors: List[str] = []

    for key, spec in schema.items():
        full_path = f"{path}.{key}" if path else key

        if key not in config:
            if spec.get("required", False):
                errors.append(f"Missing required field: {full_path}")
            continue

        value = config[key]
        expected_type = spec.get("type")

        if expected_type and not isinstance(value, expected_type):
            errors.append(
                f"Invalid type for {full_path}: expected {expected_type.__name__}"
            )

        # Nested validation
        if spec.get("schema") and isinstance(value, dict):
            errors.extend(_validate_against_schema(value, spec["schema"], full_path))

    return errors


def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname.

    Args:
        hostname: Hostname to validate.

    Returns:
        True if valid hostname.

    Raises:
        ValidationError: If hostname is invalid.
    """
    if not hostname or not isinstance(hostname, str):
        raise ValidationError("Hostname must be a non-empty string", field="hostname")

    if len(hostname) > 255:
        raise ValidationError("Hostname too long", field="hostname")

    # RFC 1123 hostname pattern
    pattern = (
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )

    if not re.match(pattern, hostname):
        raise ValidationError(f"Invalid hostname: {hostname}", field="hostname")

    return True


def validate_username(username: str) -> bool:
    """
    Validate Unix username.

    Args:
        username: Username to validate.

    Returns:
        True if valid username.

    Raises:
        ValidationError: If username is invalid.
    """
    if not username or not isinstance(username, str):
        raise ValidationError("Username must be a non-empty string", field="username")

    # Standard Unix username pattern
    pattern = r"^[a-z_][a-z0-9_-]{0,31}$"

    if not re.match(pattern, username):
        raise ValidationError(f"Invalid username: {username}", field="username")

    return True


def validate_hash(hash_value: str, algorithm: str = "sha256") -> bool:
    """
    Validate a hash string.

    Args:
        hash_value: Hash string to validate.
        algorithm: Expected algorithm (md5, sha1, sha256, sha512).

    Returns:
        True if valid hash.

    Raises:
        ValidationError: If hash is invalid.
    """
    if not hash_value or not isinstance(hash_value, str):
        raise ValidationError("Hash must be a non-empty string", field="hash")

    expected_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "sha512": 128,
    }

    expected_len = expected_lengths.get(algorithm.lower())
    if not expected_len:
        raise ValidationError(f"Unknown hash algorithm: {algorithm}", field="algorithm")

    if len(hash_value) != expected_len:
        raise ValidationError(
            f"Invalid {algorithm} hash length: expected {expected_len}, got {len(hash_value)}",
            field="hash",
        )

    if not re.match(r"^[a-fA-F0-9]+$", hash_value):
        raise ValidationError("Hash contains invalid characters", field="hash")
    return True



