"""
crypto/key_derivation.py - PBKDF2 Key Derivation

Uses PBKDF2-HMAC-SHA256 to derive a 256-bit encryption key from a user password.

Design Decisions:
  - 600,000 iterations: Aligns with NIST SP 800-63B recommendations for
    PBKDF2-HMAC-SHA256. This makes offline brute-force attacks computationally
    expensive (~0.5-2 seconds per attempt on modern hardware).
  - 16-byte (128-bit) random salt: Ensures that two users with the same password
    produce different encryption keys, defeating rainbow table attacks.
  - Per-file salt: File encryption keys are derived independently per file using
    a fresh salt each time, preventing key reuse across files.
"""
import os
import hashlib
import hmac
import base64
from config import settings


def generate_salt() -> bytes:
    """
    Generate a cryptographically secure random salt.
    Uses os.urandom which calls the OS CSPRNG (CryptGenRandom on Windows,
    /dev/urandom on Linux/Mac).
    """
    return os.urandom(settings.SALT_LENGTH)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The user's plaintext password (string).
        salt: A cryptographically random 16-byte salt.

    Returns:
        32-byte (256-bit) derived key suitable for AES-256.

    Security Notes:
        - The derived key is NEVER stored. It is only held in memory during the
          encrypt/decrypt operation and then discarded.
        - The salt IS stored (in the database alongside ciphertext) — salts are
          not secret; they exist to prevent precomputation attacks.
    """
    key = hashlib.pbkdf2_hmac(
        hash_name=settings.PBKDF2_HASH,
        password=password.encode("utf-8"),
        salt=salt,
        iterations=settings.PBKDF2_ITERATIONS,
        dklen=settings.AES_KEY_LENGTH,
    )
    return key


def derive_key_from_password(password: str, salt_b64: str) -> bytes:
    """
    Convenience wrapper: derive key from password and a base64-encoded salt.

    Args:
        password: User plaintext password.
        salt_b64: Base64-encoded salt string (as stored in database).

    Returns:
        32-byte derived key.
    """
    salt = base64.b64decode(salt_b64)
    return derive_key(password, salt)


def hash_password(password: str) -> str:
    """
    Hash a password for storage.

    Uses SHA-256 pre-hashing to convert the password to a fixed 64-byte hex
    digest, then bcrypt that. This sidesteps bcrypt's 72-byte truncation limit
    and is a well-known secure pattern (used by Django, etc.).

    This is used for LOGIN AUTHENTICATION, not for encryption key derivation.

    Returns:
        bcrypt hash string (includes salt — bcrypt handles this internally).
    """
    import bcrypt
    import hashlib
    # Pre-hash with SHA-256 to avoid bcrypt 72-byte limit
    pw_bytes = hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8")
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.

    Returns:
        True if password matches, False otherwise.
        bcrypt.checkpw runs in constant time to prevent timing attacks.
    """
    import bcrypt
    import hashlib
    pw_bytes = hashlib.sha256(plain_password.encode("utf-8")).hexdigest().encode("utf-8")
    return bcrypt.checkpw(pw_bytes, hashed_password.encode("utf-8"))
