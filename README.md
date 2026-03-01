# SecureVault

> **AES-256-GCM encrypted file storage — zero plaintext storage, secure by design.**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green.svg)](https://fastapi.tiangolo.com)
[![AES-256-GCM](https://img.shields.io/badge/Crypto-AES--256--GCM-yellow.svg)](#cryptographic-design)
[![PBKDF2](https://img.shields.io/badge/KDF-PBKDF2--HMAC--SHA256-orange.svg)](#key-derivation)

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        Browser (Client)                          │
│   ● Sends form data (password + file) over HTTPS POST           │
│   ● Receives only ciphertext metadata (filename, size, date)    │
└─────────────────────────┬────────────────────────────────────────┘
                          │ HTTPS (TLS 1.3)
┌─────────────────────────▼────────────────────────────────────────┐
│                    FastAPI Web Server                             │
│  ┌─────────────┐  ┌───────────────┐  ┌───────────────────────┐  │
│  │ routes.py   │  │  SecureHeader │  │  Rate Limiter (slowapi)│  │
│  │ (Auth/Vault)│  │  Middleware   │  │  5 req/min on /login   │  │
│  └──────┬──────┘  └───────────────┘  └───────────────────────┘  │
│         │                                                         │
│  ┌──────▼──────────────────────────────────────────────────┐     │
│  │              Cryptographic Layer (in memory)             │     │
│  │                                                          │     │
│  │  [Password] ──PBKDF2(600k)──► [256-bit AES Key]        │     │
│  │  [Plaintext] + [Key] + [IV] ──AES-256-GCM──► [Cipher]  │     │
│  │  [Key] ──────────────────────────────────────► deleted  │     │
│  └──────┬──────────────────────────────────────────────────┘     │
│         │                                                         │
│  ┌──────▼──────────┐    ┌────────────────────────────────────┐   │
│  │  SQLite DB      │    │  Vault Directory (disk)            │   │
│  │  users          │    │  xxxxxxxx.enc  ← ciphertext only   │   │
│  │  encrypted_files│    │  yyyyyyyy.enc                      │   │
│  │  audit_logs     │    │  (UUID filenames, no plaintext)    │   │
│  └─────────────────┘    └────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
securevault_web/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app factory, middleware, startup
│   ├── routes.py            # Auth + file management endpoints
│   ├── models.py            # SQLAlchemy ORM (User, EncryptedFile, AuditLog)
│   ├── database.py          # DB engine + session dependency
│   └── template_filters.py  # Jinja2 custom filters (filesizeformat, file_icon)
│
├── crypto/
│   ├── __init__.py
│   ├── encryption.py        # AES-256-GCM encrypt/decrypt
│   ├── key_derivation.py    # PBKDF2, bcrypt password hashing
│   └── integrity.py         # HMAC-SHA256 utilities, CSRF token generation
│
├── storage/
│   ├── __init__.py
│   └── vault_manager.py     # Encrypted file I/O, path traversal prevention
│
├── templates/
│   ├── base.html            # Base layout with navbar, secure footer
│   ├── index.html           # Landing page
│   ├── login.html           # Login form with CSRF
│   ├── register.html        # Registration form with password strength
│   ├── vault.html           # File management dashboard
│   ├── audit.html           # Security audit log view
│   └── error.html           # Error page
│
├── static/
│   ├── css/main.css         # Design system (dark glassmorphism)
│   └── js/main.js           # UI interactions, drag-and-drop, modal
│
├── report/
│   └── threat_model.py      # Printable threat model documentation
│
├── config.py                # Centralized settings (env-based)
├── requirements.txt
├── benchmark.py             # Crypto performance benchmark
└── README.md
```

---

## Cryptographic Design

### Key Derivation — PBKDF2-HMAC-SHA256

| Parameter   | Value              | Rationale                                              |
|-------------|--------------------|---------------------------------------------------------|
| Algorithm   | HMAC-SHA256        | NIST recommended for PBKDF2                            |
| Iterations  | 600,000            | NIST SP 800-63B minimum for PBKDF2-SHA256 (2023)       |
| Salt        | 16 bytes (random)  | Per-file, prevents rainbow table precomputation         |
| Output      | 32 bytes (256-bit) | Direct AES-256 key material                            |

**Two separate secrets:**
- **Authentication**: User password → `bcrypt(cost=12)` → stored hash
- **Encryption**: User password → `PBKDF2(salt_per_file, 600k)` → AES key (never stored)

### Encryption — AES-256-GCM

| Parameter          | Value               | Rationale                                              |
|--------------------|---------------------|---------------------------------------------------------|
| Algorithm          | AES-256-GCM         | AEAD: combines confidentiality + integrity              |
| Key size           | 256 bits            | Maximum AES key size                                   |
| IV (Nonce)         | 12 bytes (random)   | NIST recommended for GCM, fresh per file               |
| Auth Tag           | 128 bits (16 bytes) | Maximum GCM tag length                                 |
| Associated Data    | filename (bytes)    | Binds ciphertext to filename (prevents swap attacks)    |

**Why GCM over CBC + HMAC?**
- GCM is an authenticated encryption scheme — no separate MAC step needed
- GCM tag verification happens *before* any plaintext is returned (decrypt-and-verify atomically)
- CBC + HMAC requires careful ordering (encrypt-then-MAC) to avoid padding oracle attacks

### Storage Layout

```
Database row (EncryptedFile):
  original_filename : "document.pdf"       ← displayed in UI only
  vault_path        : "a3f9c1d7...enc"     ← UUID-based, unguessable
  file_iv           : base64(12 random bytes)
  file_salt         : base64(16 random bytes)
  file_size_bytes   : 102400               ← original plaintext size
  encrypted_size_bytes : 102416            ← ciphertext + 16 GCM tag bytes

Disk (vault_data/a3f9c1d7...enc):
  raw bytes: ciphertext || GCM_tag(16B)    ← ONLY ciphertext, ever
```

---

## Security Features

| Feature                    | Implementation                                        |
|----------------------------|-------------------------------------------------------|
| Password hashing           | bcrypt (cost=12) via passlib                         |
| Encryption key derivation  | PBKDF2-HMAC-SHA256, 600k iterations, per-file salt   |
| File encryption            | AES-256-GCM, unique IV per file                      |
| Integrity protection       | GCM authentication tag (128-bit)                     |
| Session security           | Signed cookies (itsdangerous), HTTPOnly, SameSite=Strict |
| CSRF protection            | Double-submit cookie pattern                         |
| Rate limiting              | slowapi — 5 logins/min per IP                        |
| Account lockout            | 5 failures → 5-minute lockout                        |
| Path traversal prevention  | UUID vault filenames, Path.resolve() validation      |
| Secure headers             | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Audit logging              | All auth events and file operations logged with IP   |
| Input validation           | File size limit, username length, password length    |

---

## Running Locally

### 1. Install Dependencies

```bash
cd securevault_web
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)

Create a `.env` file to override defaults:

```env
SECRET_KEY=your-64-char-hex-secret-key-here
DEBUG=false
VAULT_DIR=./vault_data
MAX_FILE_SIZE_MB=50
SESSION_MAX_AGE=3600
```

Generate a secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Start the Server

```bash
cd securevault_web
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open: http://127.0.0.1:8000

### 4. Run Benchmark

```bash
cd securevault_web
python benchmark.py
```

### 5. View Threat Model

```bash
cd securevault_web
python report/threat_model.py
```

---

## Testing Attack Scenarios

### Simulating File Tampering

```bash
# 1. Upload a file via the UI
# 2. Find the vault_path in the DB:
sqlite3 securevault.db "SELECT vault_path FROM encrypted_files LIMIT 1;"

# 3. Flip a byte in the ciphertext:
python -c "
import sys
path = 'vault_data/YOUR_VAULT_FILE.enc'
data = bytearray(open(path, 'rb').read())
data[50] ^= 0xFF  # flip byte 50
open(path, 'wb').write(data)
print('Tampered.')
"

# 4. Try to download the file via UI → should get:
#    'File integrity check failed. File may have been tampered with.'
```

### Simulating Brute-Force Login

```bash
# Send 6 rapid POST requests to /login with wrong password:
for i in $(seq 1 6); do
  curl -s -X POST http://127.0.0.1:8000/login \
    -d "username=testuser&password=wrong&csrf_token=$(curl -sc /tmp/c http://127.0.0.1:8000/login | grep -oP '(?<=value=")[^"]+' | tail -1)" \
    -b /tmp/c -c /tmp/c | grep -o "locked\|remaining"
done
# After 5 attempts: "Account locked. Try again in 300 seconds."
```

### Testing Rate Limiting

```bash
# More than 5 POST /login requests per minute from same IP → HTTP 429
for i in $(seq 1 10); do
  curl -o /dev/null -s -w "%{http_code}\n" -X POST http://127.0.0.1:8000/login \
    -d "username=x&password=y&csrf_token=z"
done
```

### Testing CSRF Protection

```bash
# POST to /vault/upload without matching CSRF token → HTTP 403
curl -X POST http://127.0.0.1:8000/vault/upload \
  -H "Cookie: sv_session=fake" \
  -F "password=test" \
  -F "csrf_token=invalid_token" \
  -F "file=@/tmp/test.txt"
# Expected: 403 CSRF verification failed
```

---

## Threat Model

See [report/threat_model.py](report/threat_model.py) for the full 8-threat catalog.

**Key threats addressed:**

| Threat                   | Mitigation                                        |
|--------------------------|---------------------------------------------------|
| Offline brute-force      | bcrypt + PBKDF2 (600k) slow down guessing         |
| Online brute-force       | Rate limiting + account lockout                   |
| File tampering           | AES-GCM 128-bit authentication tag                |
| CSRF attacks             | Double-submit cookie pattern                      |
| XSS                      | HTTPOnly cookies + CSP + Jinja2 auto-escaping     |
| Path traversal           | UUID vault filenames + path validation            |
| Session hijacking        | Signed cookies + HTTPOnly + SameSite=Strict       |
| IV/nonce reuse           | Fresh os.urandom() IV per file + per-file salt    |

---

## Limitations

1. **No HTTPS by default** — Deploy with reverse proxy (nginx + Let's Encrypt) in production. Enable `Secure` flag on cookies.
2. **Python key memory** — Python's GC doesn't guarantee immediate key zeroing. Use PyNaCl/libsodium for explicit memory clearing in production.
3. **SQLite** — Not suitable for multi-process deployments. Use PostgreSQL for production.
4. **No 2FA** — Password is the single authentication factor.
5. **Distributed attacks** — Per-IP rate limiting is bypassed by botnets. Add CAPTCHA and global account-level rate limits.

---

## Future Improvements

- [ ] HTTPS enforced + HSTS preload header
- [ ] TOTP/WebAuthn second factor
- [ ] Argon2id to replace bcrypt (memory-hard, more resistant to GPU attacks)
- [ ] File sharing via asymmetric key wrapping (RSA-OAEP or ECDH)
- [ ] WebCrypto API for zero-knowledge client-side encryption
- [ ] Redis-backed distributed rate limiting
- [ ] File deduplication via content-addressed storage (hash-then-encrypt)
- [ ] Admin dashboard with full audit log review
- [ ] Docker deployment configuration

---

## Dependencies

| Package         | Version  | Purpose                                        |
|-----------------|----------|------------------------------------------------|
| fastapi         | 0.110    | Web framework                                  |
| uvicorn         | 0.29     | ASGI server                                    |
| cryptography    | 42.0     | AES-256-GCM, PBKDF2 (hazmat layer)             |
| passlib[bcrypt] | 1.7      | bcrypt password hashing                        |
| sqlalchemy      | 2.0      | ORM + SQLite                                   |
| itsdangerous    | 2.1      | Signed session tokens                          |
| slowapi         | 0.1      | Rate limiting                                  |
| jinja2          | 3.1      | Server-side templates                          |
| python-dotenv   | 1.0      | Environment variable loading                   |
| aiofiles        | 23.2     | Async file I/O                                 |
