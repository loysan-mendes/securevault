"""
crypto/encryption.py - AES-256 GCM Encryption / Decryption

Design Decisions:
  - AES-256-GCM (Galois/Counter Mode) is chosen because:
      1. Authenticated Encryption with Associated Data (AEAD): The GCM authentication
         tag (128-bit) provides both confidentiality AND integrity in one primitive.
         This eliminates the need for a separate HMAC step and avoids encrypt-then-MAC
         composition errors.
      2. Parallelizable: Unlike CBC, GCM allows parallel encryption of blocks.
      3. Industry standard: Used in TLS 1.3, Signal, and recommended by NIST.

  - 12-byte (96-bit) IV/Nonce: This is the NIST-recommended IV size for GCM.
    A fresh random IV is generated for every single encryption operation using
    os.urandom() (CSPRNG). This is critical — GCM nonce reuse with the same key
    is catastrophic and completely breaks confidentiality and integrity.

  - The GCM tag verifies both the ciphertext authenticity and optional
    Associated Data (AAD). We pass the original filename as AAD to bind the
    ciphertext to its intended filename, preventing file-swapping attacks.

  - Plaintext is never written to disk. Encryption occurs entirely in memory.
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import settings


def generate_iv() -> bytes:
    """
    Generate a cryptographically secure random IV (nonce) for AES-GCM.

    The IV MUST be unique for every encryption with the same key.
    Random 96-bit IVs give a collision probability < 2^-32 after
    ~4 billion encryptions — safe for per-file usage.

    Returns:
        12 bytes of random IV data.
    """
    return os.urandom(settings.IV_LENGTH)


def encrypt_data(plaintext: bytes, key: bytes, iv: bytes, associated_data: bytes = b"") -> bytes:
    """
    Encrypt plaintext data using AES-256-GCM.

    Args:
        plaintext: Raw file bytes to encrypt.
        key: 32-byte (256-bit) derived encryption key.
        iv: 12-byte random nonce (must be unique per (key, iv) pair).
        associated_data: Optional bytes authenticated but not encrypted
                         (e.g., filename — ensures ciphertext is bound to filename).

    Returns:
        ciphertext + 16-byte GCM authentication tag (concatenated by cryptography lib).

    Raises:
        ValueError: If key or IV have incorrect lengths.
    """
    if len(key) != settings.AES_KEY_LENGTH:
        raise ValueError(f"Key must be exactly {settings.AES_KEY_LENGTH} bytes, got {len(key)}")
    if len(iv) != settings.IV_LENGTH:
        raise ValueError(f"IV must be exactly {settings.IV_LENGTH} bytes, got {len(iv)}")

    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag (16 bytes appended)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, associated_data if associated_data else None)
    return ciphertext_with_tag


def decrypt_data(ciphertext_with_tag: bytes, key: bytes, iv: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt AES-256-GCM ciphertext and verify authentication tag.

    The GCM tag verification happens BEFORE any plaintext is returned.
    If the ciphertext has been tampered with, the associated data doesn't match,
    or the key/IV are wrong, an InvalidTag exception is raised and NO plaintext
    is ever exposed.

    Args:
        ciphertext_with_tag: Encrypted bytes with 16-byte GCM tag appended.
        key: 32-byte derived encryption key.
        iv: 12-byte nonce used during encryption.
        associated_data: Must match the AAD used during encryption exactly.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If integrity check fails (tampered/wrong key).
        ValueError: If key or IV have incorrect lengths.
    """
    if len(key) != settings.AES_KEY_LENGTH:
        raise ValueError(f"Key must be exactly {settings.AES_KEY_LENGTH} bytes, got {len(key)}")
    if len(iv) != settings.IV_LENGTH:
        raise ValueError(f"IV must be exactly {settings.IV_LENGTH} bytes, got {len(iv)}")

    aesgcm = AESGCM(key)
    # This will raise cryptography.exceptions.InvalidTag if verification fails
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data if associated_data else None)
    return plaintext
