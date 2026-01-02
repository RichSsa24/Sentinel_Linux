"""
Cryptographic utilities.

Provides secure hashing and cryptographic operations.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from typing import Optional


def hash_file(path: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file.

    Args:
        path: Path to file.
        algorithm: Hash algorithm (md5, sha1, sha256, sha512).

    Returns:
        Hexadecimal hash string.

    Raises:
        FileNotFoundError: If file doesn't exist.
        ValueError: If algorithm is unsupported.
    """
    valid_algorithms = {"md5", "sha1", "sha256", "sha512"}
    if algorithm.lower() not in valid_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    hasher = hashlib.new(algorithm.lower())

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def hash_string(data: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a string.

    Args:
        data: String to hash.
        algorithm: Hash algorithm.

    Returns:
        Hexadecimal hash string.
    """
    valid_algorithms = {"md5", "sha1", "sha256", "sha512"}
    if algorithm.lower() not in valid_algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    hasher = hashlib.new(algorithm.lower())
    hasher.update(data.encode("utf-8"))

    return hasher.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """
    Calculate hash of bytes.

    Args:
        data: Bytes to hash.
        algorithm: Hash algorithm.

    Returns:
        Hexadecimal hash string.
    """
    hasher = hashlib.new(algorithm.lower())
    hasher.update(data)

    return hasher.hexdigest()


def generate_event_id() -> str:
    """
    Generate unique event identifier.

    Returns:
        UUID string.
    """
    return str(uuid.uuid4())


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Token length in bytes.

    Returns:
        Hexadecimal token string.
    """
    return secrets.token_hex(length)


def verify_signature(data: bytes, signature: bytes, key: bytes) -> bool:
    """
    Verify HMAC-SHA256 signature.

    Args:
        data: Data that was signed.
        signature: Signature to verify.
        key: Secret key.

    Returns:
        True if signature is valid.
    """
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def create_signature(data: bytes, key: bytes) -> bytes:
    """
    Create HMAC-SHA256 signature.

    Args:
        data: Data to sign.
        key: Secret key.

    Returns:
        Signature bytes.
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string.
        b: Second string.

    Returns:
        True if strings are equal.
    """
    return hmac.compare_digest(a.encode(), b.encode())


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, bytes]:
    """
    Hash a password using PBKDF2.

    Args:
        password: Password to hash.
        salt: Optional salt (generated if not provided).

    Returns:
        Tuple of (hash, salt).
    """
    if salt is None:
        salt = secrets.token_bytes(32)

    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=100000,
    )

    return hash_bytes.hex(), salt


def verify_password(password: str, hash_hex: str, salt: bytes) -> bool:
    """
    Verify a password against a hash.

    Args:
        password: Password to verify.
        hash_hex: Expected hash.
        salt: Salt used for hashing.

    Returns:
        True if password matches.
    """
    computed_hash, _ = hash_password(password, salt)
    return constant_time_compare(computed_hash, hash_hex)


