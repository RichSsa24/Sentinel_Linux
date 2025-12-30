"""Tests for input validation utilities."""

from __future__ import annotations

import pytest

from src.utils.validators import (
    validate_ip_address,
    validate_port,
    validate_path,
    validate_hostname,
    validate_hash,
)
from src.core.exceptions import ValidationError


class TestValidateIPAddress:
    """Tests for IP address validation."""

    def test_valid_ipv4(self) -> None:
        """Valid IPv4 addresses should pass."""
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("10.0.0.1") is True
        assert validate_ip_address("127.0.0.1") is True

    def test_valid_ipv6(self) -> None:
        """Valid IPv6 addresses should pass."""
        assert validate_ip_address("::1") is True
        assert validate_ip_address("fe80::1") is True

    def test_invalid_ip(self) -> None:
        """Invalid IP addresses should raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_ip_address("invalid")

        with pytest.raises(ValidationError):
            validate_ip_address("256.256.256.256")

        with pytest.raises(ValidationError):
            validate_ip_address("")


class TestValidatePort:
    """Tests for port validation."""

    def test_valid_ports(self) -> None:
        """Valid ports should pass."""
        assert validate_port(1) is True
        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(65535) is True

    def test_invalid_ports(self) -> None:
        """Invalid ports should raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_port(0)

        with pytest.raises(ValidationError):
            validate_port(65536)

        with pytest.raises(ValidationError):
            validate_port(-1)


class TestValidatePath:
    """Tests for path validation."""

    def test_valid_path(self) -> None:
        """Valid paths should pass."""
        assert validate_path("/etc/passwd") is True
        assert validate_path("/tmp/test") is True

    def test_null_byte_rejected(self) -> None:
        """Paths with null bytes should be rejected."""
        with pytest.raises(ValidationError):
            validate_path("/etc/passwd\x00")

    def test_path_traversal_rejected(self) -> None:
        """Path traversal attempts should be rejected."""
        with pytest.raises(ValidationError):
            validate_path("/etc/../../../etc/passwd")


class TestValidateHostname:
    """Tests for hostname validation."""

    def test_valid_hostnames(self) -> None:
        """Valid hostnames should pass."""
        assert validate_hostname("localhost") is True
        assert validate_hostname("server-01") is True
        assert validate_hostname("web.example.com") is True

    def test_invalid_hostnames(self) -> None:
        """Invalid hostnames should raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_hostname("-invalid")

        with pytest.raises(ValidationError):
            validate_hostname("")


class TestValidateHash:
    """Tests for hash validation."""

    def test_valid_md5(self) -> None:
        """Valid MD5 hashes should pass."""
        assert validate_hash("d41d8cd98f00b204e9800998ecf8427e", "md5") is True

    def test_valid_sha256(self) -> None:
        """Valid SHA256 hashes should pass."""
        valid_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert validate_hash(valid_sha256, "sha256") is True

    def test_invalid_hash_length(self) -> None:
        """Invalid hash lengths should raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_hash("abc123", "sha256")

    def test_invalid_hash_chars(self) -> None:
        """Invalid characters in hash should raise ValidationError."""
        with pytest.raises(ValidationError):
            validate_hash("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "md5")



