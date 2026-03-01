"""
app/database.py - SQLAlchemy Database Setup

Uses SQLite with SQLAlchemy ORM. The database stores only:
  - User account metadata (username, bcrypt password hash, encryption salt)
  - File metadata (path to ciphertext, IV, salt, original filename)

NO plaintext file content is ever stored in the database.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import sys
import os

# Add parent to path so config is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite in FastAPI
    echo=settings.DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency: yields a database session and ensures cleanup.
    Usage: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Create all tables. Called at application startup.
    In production, use Alembic for migrations.
    """
    from app import models  # noqa: F401 — import models to register them with Base
    Base.metadata.create_all(bind=engine)
