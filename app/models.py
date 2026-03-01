"""
app/models.py - SQLAlchemy ORM Models

Two core models:
  - User: Authentication data + per-user encryption salt
  - EncryptedFile: Metadata for each uploaded file (no plaintext stored)

Security Design Notes:
  - `password_hash`: bcrypt hash. Raw password is never persisted.
  - `encryption_salt`: Used to derive per-user base key with PBKDF2. Stored as
    base64 string. Salts are not secret — they prevent precomputation.
  - `file_iv`: The AES-GCM nonce for this specific file. Unique per file.
  - `file_salt`: Per-file salt for PBKDF2 key derivation. Separate from the
    user-level encryption_salt to ensure unique encryption keys per file.
  - `vault_path`: Absolute path to the encrypted ciphertext on disk.
"""
import base64
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, BigInteger, Boolean
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)  # bcrypt hash
    # Per-user encryption salt (base64-encoded 16 bytes)
    # Used to derive a master key from the user's password for key derivation
    encryption_salt = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    files = relationship("EncryptedFile", back_populates="owner", cascade="all, delete-orphan")


class EncryptedFile(Base):
    __tablename__ = "encrypted_files"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    original_filename = Column(String(256), nullable=False)  # Original name for display
    vault_path = Column(String(512), nullable=False, unique=True)  # Path to ciphertext on disk
    # AES-GCM nonce for this file (base64-encoded 12 bytes). Unique per encryption.
    file_iv = Column(String(32), nullable=False)
    # PBKDF2 salt for this file's key derivation (base64-encoded 16 bytes).
    file_salt = Column(String(32), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)  # Original plaintext size
    encrypted_size_bytes = Column(BigInteger, nullable=False)  # Ciphertext size on disk
    mime_type = Column(String(128), nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="files")


class AuditLog(Base):
    """
    Security audit trail. Records authentication events and file operations.
    Retained for security analysis.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(64), nullable=True)  # Stored directly in case user is deleted
    event_type = Column(String(64), nullable=False)  # e.g. "login_success", "login_failure"
    details = Column(String(512), nullable=True)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
