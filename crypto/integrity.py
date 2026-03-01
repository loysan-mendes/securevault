"""
crypto/integrity.py - HMAC-SHA256 Integrity Helpers

NOTE: With AES-256-GCM, the GCM authentication tag serves as the primary
integrity mechanism (Authenticated Encryption). This module provides
supplementary HMAC utilities for:
  1. Verifying file metadata integrity (not covered by GCM tag alone)
  2. Generating secure CSRF tokens
  3. Utility comparisons in constant time

These helpers use HMAC-SHA256 with the application's SECRET_KEY as the MAC key.
"""
import hmac
import hashlib
import base64
import os
from config import settings


def compute_hmac(data: bytes, key: bytes = None) -> str:
    """
    Compute HMAC-SHA256 of data.

    Args:
        data: Bytes to authenticate.
        key: MAC key (defaults to app SECRET_KEY as bytes).

    Returns:
        Base64-encoded HMAC digest string.
    """
    if key is None:
        key = settings.SECRET_KEY.encode("utf-8")
    mac = hmac.new(key, data, hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("utf-8")


def verify_hmac(data: bytes, expected_mac: str, key: bytes = None) -> bool:
    """
    Verify HMAC-SHA256 in constant time to prevent timing attacks.

    Uses hmac.compare_digest() which is specifically designed to prevent
    timing side-channel attacks by always taking the same time regardless
    of where the strings differ.

    Args:
        data: The data to re-MAC and compare.
        expected_mac: Base64-encoded expected HMAC value.
        key: MAC key (defaults to app SECRET_KEY as bytes).

    Returns:
        True if MAC matches, False otherwise.
    """
    if key is None:
        key = settings.SECRET_KEY.encode("utf-8")
    computed = compute_hmac(data, key)
    # constant-time comparison
    return hmac.compare_digest(computed.encode("utf-8"), expected_mac.encode("utf-8"))


def generate_secure_token(nbytes: int = 32) -> str:
    """
    Generate a URL-safe, cryptographically secure random token.
    Used for CSRF tokens and session identifiers.

    Args:
        nbytes: Number of random bytes (default 32 = 256 bits of entropy).

    Returns:
        URL-safe base64-encoded token string.
    """
    return base64.urlsafe_b64encode(os.urandom(nbytes)).decode("utf-8").rstrip("=")
