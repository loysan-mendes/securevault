"""
storage/vault_manager.py - Encrypted File I/O

Handles writing and reading encrypted file blobs to/from the vault directory.
The vault directory contains ONLY ciphertext — never plaintext.

Path Traversal Prevention:
  - All vault filenames are UUID-based, generated internally.
  - The original filename is stored only in the database, never used as a path.
  - vault_path is validated to be within the configured VAULT_DIR before any I/O.
"""
import os
import uuid
import logging
from pathlib import Path
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

logger = logging.getLogger(__name__)


def _get_vault_dir() -> Path:
    """
    Return the vault directory Path, creating it if needed.
    """
    vault = Path(settings.VAULT_DIR).resolve()
    vault.mkdir(parents=True, exist_ok=True)
    return vault


def _safe_vault_path(filename: str) -> Path:
    """
    Resolve a vault filename and verify it stays within VAULT_DIR.
    Raises ValueError if path traversal is detected.
    """
    vault_dir = _get_vault_dir()
    resolved = (vault_dir / filename).resolve()
    if not str(resolved).startswith(str(vault_dir)):
        raise ValueError(f"Path traversal detected: {filename}")
    return resolved


def generate_vault_filename() -> str:
    """
    Generate a unique, opaque vault filename using UUID4.
    The filename carries no information about the original file.
    """
    return f"{uuid.uuid4().hex}.enc"


def write_encrypted_file(ciphertext: bytes) -> str:
    """
    Write encrypted bytes to the vault directory.

    Args:
        ciphertext: Encrypted file bytes (ciphertext + GCM tag).

    Returns:
        The vault filename (UUID-based, not the original filename).
    """
    vault_filename = generate_vault_filename()
    vault_path = _safe_vault_path(vault_filename)

    with open(vault_path, "wb") as f:
        f.write(ciphertext)

    logger.info(f"Wrote {len(ciphertext)} encrypted bytes to {vault_filename}")
    return vault_filename


def read_encrypted_file(vault_filename: str) -> bytes:
    """
    Read encrypted bytes from the vault directory.

    Args:
        vault_filename: The UUID-based filename stored in the database.

    Returns:
        Raw ciphertext bytes.

    Raises:
        FileNotFoundError: If the vault file doesn't exist.
        ValueError: If path traversal is detected.
    """
    vault_path = _safe_vault_path(vault_filename)

    if not vault_path.exists():
        raise FileNotFoundError(f"Vault file not found: {vault_filename}")

    with open(vault_path, "rb") as f:
        data = f.read()

    logger.info(f"Read {len(data)} encrypted bytes from {vault_filename}")
    return data


def delete_encrypted_file(vault_filename: str) -> bool:
    """
    Securely delete an encrypted file from the vault.

    Args:
        vault_filename: UUID-based vault filename.

    Returns:
        True if deleted, False if file not found.
    """
    try:
        vault_path = _safe_vault_path(vault_filename)
        if vault_path.exists():
            vault_path.unlink()
            logger.info(f"Deleted vault file: {vault_filename}")
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting vault file {vault_filename}: {e}")
        return False


def get_vault_file_size(vault_filename: str) -> int:
    """Return the size in bytes of an encrypted vault file."""
    vault_path = _safe_vault_path(vault_filename)
    return vault_path.stat().st_size
