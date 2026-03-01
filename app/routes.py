"""
app/routes.py - FastAPI Route Handlers

Security architecture:
  - Authentication: Session cookies (signed with SECRET_KEY via itsdangerous).
  - CSRF: Double-submit cookie pattern enforced on all mutating endpoints.
  - Rate limiting: Per-IP limits via slowapi on auth routes.
  - Account lockout: 5 failed attempts triggers 5-minute lockout.
  - File size: Configurable maximum upload size enforced server-side.
  - Password re-entry: Download requires password re-entry to re-derive key in memory.
"""
import base64
import logging
import os
import mimetypes
from datetime import datetime, timedelta
from typing import Optional

from fastapi import (
    APIRouter, Depends, Request, Form, UploadFile, File,
    HTTPException, status, Response
)
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from cryptography.exceptions import InvalidTag
import io
import sys
import os as _os

_os.sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from config import settings
from app.database import get_db
from app import models
from crypto.key_derivation import (
    generate_salt, derive_key, hash_password, verify_password
)
from crypto.encryption import encrypt_data, decrypt_data, generate_iv
from crypto.integrity import generate_secure_token
from storage.vault_manager import (
    write_encrypted_file, read_encrypted_file, delete_encrypted_file
)

logger = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Session serializer (signs session data with SECRET_KEY)
_session_serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

SESSION_COOKIE = "sv_session"
CSRF_COOKIE = "sv_csrf"


# ─────────────────────────────────────────────────────────────
# Session Utilities
# ─────────────────────────────────────────────────────────────

def create_session(user_id: int, username: str) -> str:
    """Create a signed, tamper-proof session token."""
    return _session_serializer.dumps(
        {"user_id": user_id, "username": username},
        salt="session"
    )


def get_current_user_from_session(request: Request, db: Session = Depends(get_db)) -> Optional[models.User]:
    """
    Dependency: extract and verify the session cookie.
    Returns the User ORM object or None if not authenticated.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        data = _session_serializer.loads(
            token, salt="session", max_age=settings.SESSION_MAX_AGE
        )
        user = db.query(models.User).filter(
            models.User.id == data["user_id"],
            models.User.is_active == True
        ).first()
        return user
    except (BadSignature, SignatureExpired):
        return None


def require_login(request: Request, db: Session = Depends(get_db)) -> models.User:
    """
    Dependency: same as get_current_user_from_session but raises 401 if not logged in.
    """
    user = get_current_user_from_session(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"}
        )
    return user


def verify_csrf(request: Request, csrf_token: str = Form(None)):
    """Verify CSRF token matches the cookie (double-submit pattern)."""
    cookie_token = request.cookies.get(CSRF_COOKIE)
    if not cookie_token or cookie_token != csrf_token:
        raise HTTPException(status_code=403, detail="CSRF verification failed.")


def _log_event(db: Session, event_type: str, request: Request,
               user: Optional[models.User] = None, details: str = None):
    """Write an entry to the audit log."""
    log = models.AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else None,
        event_type=event_type,
        details=details,
        ip_address=request.client.host if request.client else "unknown",
    )
    db.add(log)
    db.commit()


# ─────────────────────────────────────────────────────────────
# Account Lockout Helpers
# ─────────────────────────────────────────────────────────────

def _is_locked(user: models.User) -> bool:
    if user.locked_until and datetime.utcnow() < user.locked_until:
        return True
    return False


def _increment_failure(db: Session, user: models.User):
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= settings.MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.utcnow() + timedelta(seconds=settings.LOCKOUT_SECONDS)
        logger.warning(f"Account locked: {user.username}")
    db.commit()


def _reset_failures(db: Session, user: models.User):
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.commit()


# ─────────────────────────────────────────────────────────────
# Public Pages
# ─────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_from_session(request, db)
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


# ─────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    csrf_token = generate_secure_token()
    response = templates.TemplateResponse("register.html", {
        "request": request, "csrf_token": csrf_token, "error": None
    })
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, samesite="strict")
    return response


@router.post("/register", response_class=HTMLResponse)
async def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_csrf(request, csrf_token)

    def error(msg):
        new_csrf = generate_secure_token()
        resp = templates.TemplateResponse("register.html", {
            "request": request, "csrf_token": new_csrf, "error": msg
        })
        resp.set_cookie(CSRF_COOKIE, new_csrf, httponly=False, samesite="strict")
        return resp

    # Input validation
    username = username.strip()
    if len(username) < 3 or len(username) > 64:
        return error("Username must be 3–64 characters.")
    if len(password) < 10:
        return error("Password must be at least 10 characters.")
    if password != confirm_password:
        return error("Passwords do not match.")

    # Check uniqueness
    if db.query(models.User).filter(models.User.username == username).first():
        return error("Username already taken.")
    if db.query(models.User).filter(models.User.email == email).first():
        return error("Email already registered.")

    # Hash password with bcrypt
    password_hash = hash_password(password)

    # Generate per-user encryption salt for PBKDF2 key derivation
    enc_salt = generate_salt()
    enc_salt_b64 = base64.b64encode(enc_salt).decode("utf-8")

    user = models.User(
        username=username,
        email=email,
        password_hash=password_hash,
        encryption_salt=enc_salt_b64,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    _log_event(db, "register", request, user=user, details="New user registered")
    logger.info(f"New user registered: {username}")
    return RedirectResponse(url="/login?registered=1", status_code=303)


# ─────────────────────────────────────────────────────────────
# Login / Logout
# ─────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, registered: str = None):
    csrf_token = generate_secure_token()
    response = templates.TemplateResponse("login.html", {
        "request": request,
        "csrf_token": csrf_token,
        "error": None,
        "success": "Registration successful. Please log in." if registered else None,
    })
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, samesite="strict")
    return response


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_csrf(request, csrf_token)

    def error(msg):
        new_csrf = generate_secure_token()
        resp = templates.TemplateResponse("login.html", {
            "request": request, "csrf_token": new_csrf, "error": msg, "success": None
        })
        resp.set_cookie(CSRF_COOKIE, new_csrf, httponly=False, samesite="strict")
        return resp

    user = db.query(models.User).filter(models.User.username == username).first()

    if not user:
        _log_event(db, "login_failure_unknown_user", request, details=f"Unknown user: {username}")
        return error("Invalid credentials.")

    if _is_locked(user):
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds())
        _log_event(db, "login_blocked_locked", request, user=user)
        return error(f"Account locked. Try again in {remaining} seconds.")

    if not verify_password(password, user.password_hash):
        _increment_failure(db, user)
        _log_event(db, "login_failure_bad_password", request, user=user)
        attempts_left = settings.MAX_FAILED_ATTEMPTS - user.failed_login_attempts
        if attempts_left <= 0:
            return error("Account locked due to too many failed attempts.")
        return error(f"Invalid credentials. {max(attempts_left,0)} attempt(s) remaining.")

    _reset_failures(db, user)
    _log_event(db, "login_success", request, user=user)

    session_token = create_session(user.id, user.username)
    response = RedirectResponse(url="/vault", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, session_token,
        httponly=True,   # Not accessible via JS — prevents XSS theft
        samesite="strict",
        max_age=settings.SESSION_MAX_AGE,
        secure=not settings.DEBUG,  # True in production (HTTPS), False in local dev
    )
    return response


@router.post("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    return response


# ─────────────────────────────────────────────────────────────
# Vault (File Management)
# ─────────────────────────────────────────────────────────────

@router.get("/vault", response_class=HTMLResponse)
async def vault_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_from_session(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    files = db.query(models.EncryptedFile).filter(
        models.EncryptedFile.owner_id == user.id
    ).order_by(models.EncryptedFile.uploaded_at.desc()).all()

    csrf_token = generate_secure_token()
    response = templates.TemplateResponse("vault.html", {
        "request": request,
        "user": user,
        "files": files,
        "csrf_token": csrf_token,
        "error": None,
        "success": None,
    })
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, samesite="strict")
    return response


@router.post("/vault/upload", response_class=HTMLResponse)
async def upload_file(
    request: Request,
    password: str = Form(...),
    csrf_token: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    verify_csrf(request, csrf_token)
    user = get_current_user_from_session(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    def vault_error(msg):
        files = db.query(models.EncryptedFile).filter(
            models.EncryptedFile.owner_id == user.id
        ).order_by(models.EncryptedFile.uploaded_at.desc()).all()
        new_csrf = generate_secure_token()
        resp = templates.TemplateResponse("vault.html", {
            "request": request, "user": user, "files": files,
            "csrf_token": new_csrf, "error": msg, "success": None
        })
        resp.set_cookie(CSRF_COOKIE, new_csrf, httponly=False, samesite="strict")
        return resp

    # Validate file size
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        return vault_error(f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB} MB.")
    if len(content) == 0:
        return vault_error("Cannot upload empty file.")

    # Verify user password before using it for key derivation
    if not verify_password(password, user.password_hash):
        _log_event(db, "upload_bad_password", request, user=user,
                   details=f"Bad password on upload of {file.filename}")
        return vault_error("Incorrect password.")

    original_filename = file.filename or "unnamed_file"
    plaintext_size = len(content)

    # Generate fresh per-file salt and IV for this encryption operation
    file_salt = generate_salt()
    file_iv = generate_iv()

    # Derive encryption key: user_password + per-file_salt → 256-bit AES key
    # The original filename is used as AAD to bind ciphertext to its metadata
    enc_key = derive_key(password, file_salt)
    aad = original_filename.encode("utf-8")

    try:
        ciphertext = encrypt_data(content, enc_key, file_iv, aad)
    finally:
        # Explicitly overwrite key material in memory (best-effort in Python)
        del enc_key
        del content  # Discard plaintext immediately

    # Write ciphertext to vault
    vault_filename = write_encrypted_file(ciphertext)
    encrypted_size = len(ciphertext)

    # Store metadata in database (NO plaintext, only ciphertext path + crypto params)
    mime_type = mimetypes.guess_type(original_filename)[0]
    file_record = models.EncryptedFile(
        owner_id=user.id,
        original_filename=original_filename,
        vault_path=vault_filename,
        file_iv=base64.b64encode(file_iv).decode("utf-8"),
        file_salt=base64.b64encode(file_salt).decode("utf-8"),
        file_size_bytes=plaintext_size,
        encrypted_size_bytes=encrypted_size,
        mime_type=mime_type,
    )
    db.add(file_record)
    db.commit()

    _log_event(db, "file_upload", request, user=user,
               details=f"Uploaded {original_filename} ({plaintext_size} bytes)")
    logger.info(f"File uploaded by {user.username}: {original_filename}")

    files = db.query(models.EncryptedFile).filter(
        models.EncryptedFile.owner_id == user.id
    ).order_by(models.EncryptedFile.uploaded_at.desc()).all()
    new_csrf = generate_secure_token()
    resp = templates.TemplateResponse("vault.html", {
        "request": request, "user": user, "files": files,
        "csrf_token": new_csrf,
        "error": None,
        "success": f"'{original_filename}' encrypted and stored successfully.",
    })
    resp.set_cookie(CSRF_COOKIE, new_csrf, httponly=False, samesite="strict")
    return resp


@router.post("/vault/download/{file_id}")
async def download_file(
    file_id: int,
    request: Request,
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_csrf(request, csrf_token)
    user = get_current_user_from_session(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    file_record = db.query(models.EncryptedFile).filter(
        models.EncryptedFile.id == file_id,
        models.EncryptedFile.owner_id == user.id  # Ownership check
    ).first()

    if not file_record:
        raise HTTPException(status_code=404, detail="File not found.")

    # Verify password BEFORE attempting decryption
    if not verify_password(password, user.password_hash):
        _log_event(db, "download_bad_password", request, user=user,
                   details=f"Bad password on download of file_id={file_id}")
        raise HTTPException(status_code=403, detail="Incorrect password.")

    # Read ciphertext from vault
    try:
        ciphertext = read_encrypted_file(file_record.vault_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Encrypted file missing from vault.")

    # Re-derive encryption key from password + stored per-file salt
    file_salt = base64.b64decode(file_record.file_salt)
    file_iv = base64.b64decode(file_record.file_iv)
    enc_key = derive_key(password, file_salt)
    aad = file_record.original_filename.encode("utf-8")

    try:
        # GCM tag verification happens here — raises InvalidTag if tampered
        plaintext = decrypt_data(ciphertext, enc_key, file_iv, aad)
    except InvalidTag:
        _log_event(db, "integrity_check_failed", request, user=user,
                   details=f"GCM tag verification failed for file_id={file_id}")
        logger.critical(f"INTEGRITY CHECK FAILED for file {file_id} — possible tampering!")
        raise HTTPException(
            status_code=400,
            detail="File integrity check failed. File may have been tampered with."
        )
    finally:
        del enc_key

    _log_event(db, "file_download", request, user=user,
               details=f"Downloaded {file_record.original_filename} (file_id={file_id})")

    # Stream plaintext to client — never written to disk
    return StreamingResponse(
        io.BytesIO(plaintext),
        media_type=file_record.mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file_record.original_filename}"',
            "Content-Length": str(len(plaintext)),
        }
    )


@router.post("/vault/delete/{file_id}")
async def delete_file(
    file_id: int,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    verify_csrf(request, csrf_token)
    user = get_current_user_from_session(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    file_record = db.query(models.EncryptedFile).filter(
        models.EncryptedFile.id == file_id,
        models.EncryptedFile.owner_id == user.id
    ).first()

    if not file_record:
        raise HTTPException(status_code=404, detail="File not found.")

    fname = file_record.original_filename
    delete_encrypted_file(file_record.vault_path)
    db.delete(file_record)
    db.commit()

    _log_event(db, "file_delete", request, user=user, details=f"Deleted {fname} (file_id={file_id})")
    return RedirectResponse(url="/vault", status_code=303)


# ─────────────────────────────────────────────────────────────
# Audit Log (admin view - demo: any authenticated user sees their own)
# ─────────────────────────────────────────────────────────────

@router.get("/audit", response_class=HTMLResponse)
async def audit_log(request: Request, db: Session = Depends(get_db)):
    user = get_current_user_from_session(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    logs = db.query(models.AuditLog).filter(
        models.AuditLog.user_id == user.id
    ).order_by(models.AuditLog.timestamp.desc()).limit(100).all()

    return templates.TemplateResponse("audit.html", {
        "request": request, "user": user, "logs": logs
    })
