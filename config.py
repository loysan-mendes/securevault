"""
config.py - Application Configuration

All configuration is loaded from environment variables using .env file.
Sensitive values like SECRET_KEY are never hardcoded here.
"""
import os
import secrets
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Application
    APP_NAME: str = "SecureVault"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Security
    # SECRET_KEY is used for signing session cookies and CSRF tokens.
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_hex(32))
    SESSION_MAX_AGE: int = int(os.getenv("SESSION_MAX_AGE", 3600))  # 1 hour

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./securevault.db")

    # Storage
    # Encrypted file vault directory — never stores plaintext
    VAULT_DIR: str = os.getenv("VAULT_DIR", "./vault_data")
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", 50))

    # Cryptographic constants (do NOT change these without re-encrypting all files)
    PBKDF2_ITERATIONS: int = 600_000   # NIST recommended minimum for PBKDF2-HMAC-SHA256
    PBKDF2_HASH: str = "sha256"
    AES_KEY_LENGTH: int = 32           # 256 bits
    SALT_LENGTH: int = 16              # 128 bits
    IV_LENGTH: int = 12                # 96 bits — optimal for AES-GCM
    GCM_TAG_LENGTH: int = 16           # 128-bit authentication tag

    # Rate limiting
    LOGIN_RATE_LIMIT: str = os.getenv("LOGIN_RATE_LIMIT", "5/minute")
    REGISTER_RATE_LIMIT: str = os.getenv("REGISTER_RATE_LIMIT", "3/minute")
    UPLOAD_RATE_LIMIT: str = os.getenv("UPLOAD_RATE_LIMIT", "10/minute")

    # Account lockout
    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_SECONDS: int = 300  # 5 minutes


settings = Settings()
