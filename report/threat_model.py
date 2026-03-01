"""
report/threat_model.py - Security Threat Model Documentation Generator

Prints a structured threat model for SecureVault.
Run with: python report/threat_model.py
"""

THREAT_MODEL = """
╔══════════════════════════════════════════════════════════════════╗
║           SecureVault — Security Threat Model Report             ║
╚══════════════════════════════════════════════════════════════════╝

1. SYSTEM OVERVIEW
──────────────────
SecureVault is a web-based encrypted file storage system. Users upload files
that are encrypted in memory using AES-256-GCM before disk storage. The
application stores only ciphertext, IVs, salts, and bcrypt password hashes.
No plaintext file content or raw passwords are ever persisted.

2. ASSETS TO PROTECT
─────────────────────
  [A1] User file contents (plaintext)
  [A2] User credentials (passwords)
  [A3] Derived encryption keys (in memory only)
  [A4] Session tokens (in signed cookies)
  [A5] Database (user metadata, encrypted file metadata)

3. TRUST BOUNDARY
──────────────────
  Trusted  : Server-side Python code, OS CSPRNG
  Untrusted: Network, User browser, Uploaded file content, HTTP headers

4. THREAT CATALOG
──────────────────

  ┌─────────────────────────────────────────────────────────────────┐
  │ T1: Offline Brute-Force / Dictionary Attack on Password         │
  ├─────────────────────────────────────────────────────────────────┤
  │ Attacker obtains database dump and runs offline password guessing│
  │ against bcrypt hashes or PBKDF2-derived keys.                   │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • Password hash: bcrypt (cost factor 12) — ~100ms/attempt      │
  │  • Encryption key: PBKDF2-HMAC-SHA256, 600k iterations          │
  │    → ~1–2 guesses/sec/core                                      │
  │  • Per-user unique salt → rainbow tables ineffective            │
  │  • Attacker must defeat BOTH bcrypt AND PBKDF2 independently    │
  │                                                                 │
  │ RESIDUAL RISK: Weak user passwords remain exploitable.          │
  │ RECOMMENDATION: Enforce minimum password complexity (10+ chars). │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ T2: Online Brute-Force / Credential Stuffing                    │
  ├─────────────────────────────────────────────────────────────────┤
  │ Automated login attempts from the web using known username/      │
  │ password combos or dictionary attacks.                          │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • Rate limiting: 5 login attempts per minute per IP            │
  │  • Account lockout: 5 failures → 5-minute lockout              │
  │  • Audit logging: All failures logged with IP and timestamp     │
  │                                                                 │
  │ RESIDUAL RISK: Distributed attacks from many IPs bypass         │
  │ per-IP rate limiting. Fix: CAPTCHA, account-level rate limits.  │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ T3: File Tampering / Ciphertext Manipulation                    │
  ├─────────────────────────────────────────────────────────────────┤
  │ Attacker with disk access modifies ciphertext bytes to alter    │
  │ decrypted output (bit-flip attacks, chosen-ciphertext attacks). │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • AES-256-GCM: 128-bit authentication tag detects ANY change  │
  │  • Filename used as Associated Data (AAD): file-swapping attack │
  │    fails (different filename = wrong AAD = tag verification fail)│
  │  • Decryption aborted BEFORE any plaintext returned on failure  │
  │  • Audit log records integrity check failures                   │
  │                                                                 │
  │ RESIDUAL RISK: None for ciphertext layer.                       │
  │ GCM provides provably secure authenticated encryption.          │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ T4: Cross-Site Request Forgery (CSRF)                           │
  ├─────────────────────────────────────────────────────────────────┤
  │ Attacker tricks authenticated user into submitting a malicious  │
  │ request (e.g., delete all files, upload malware).              │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • Double-submit cookie pattern: CSRF token in cookie AND form  │
  │  • SameSite=Strict cookie attribute on session cookie           │
  │  • All mutating endpoints (POST) verify CSRF token             │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ T5: Cross-Site Scripting (XSS)                                  │
  ├─────────────────────────────────────────────────────────────────┤
  │ Attacker injects script into page to steal session cookies or   │
  │ exfiltrate data.                                                │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • Jinja2 auto-escapes all template variables by default        │
  │  • HTTPOnly session cookie: not accessible via JavaScript       │
  │  • Content-Security-Policy header restricts script sources      │
  │  • X-Content-Type-Options: nosniff prevents MIME confusion       │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ T6: Path Traversal (File Inclusion)                             │
  ├─────────────────────────────────────────────────────────────────┤
  │ Attacker crafts a filename containing "../" to read/write       │
  │ arbitrary files outside the vault directory.                    │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • All vault files named with UUID4 hex — no user input used    │
  │    as filename on disk                                          │
  │  • vault_path resolved with Path.resolve() and validated to     │
  │    remain within VAULT_DIR before any I/O                       │
  │  • Original filename stored only in the database, never as path │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ T7: Session Hijacking                                           │
  ├─────────────────────────────────────────────────────────────────┤
  │ Attacker intercepts or steals a valid session token.            │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • Session tokens signed with HMAC using SECRET_KEY            │
  │  • HTTPOnly cookie: not accessible via JavaScript              │
  │  • SameSite=Strict: not sent on cross-site requests            │
  │  • Session expiry: 1 hour (configurable)                       │
  │  • Secure flag: set this to True in production with HTTPS      │
  │                                                                 │
  │ RESIDUAL RISK: Without HTTPS, sessions vulnerable to MitM.     │
  │ RECOMMENDATION: Deploy with HTTPS + Secure cookie + HSTS.      │
  └─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │ T8: Nonce/IV Reuse (Catastrophic for GCM)                       │
  ├─────────────────────────────────────────────────────────────────┤
  │ If the same (key, IV) pair is used twice in GCM mode, both      │
  │ confidentiality and authenticity are completely broken.         │
  │                                                                 │
  │ MITIGATIONS:                                                    │
  │  • Fresh random 96-bit IV generated via os.urandom() per file  │
  │  • Per-file PBKDF2 salt ensures different keys per file        │
  │  • Probability of IV collision: < 2^-32 after 4B encryptions   │
  │    (safe for realistic usage volumes)                           │
  └─────────────────────────────────────────────────────────────────┘

5. ATTACK SCENARIOS TESTED
───────────────────────────
  [S1] Tamper test: Flip byte in ciphertext file → GCM tag fails → download aborted ✓
  [S2] Wrong password: Decryption returns InvalidTag (key mismatch) ✓
  [S3] File swap: Try to download ciphertext with wrong filename (AAD mismatch) ✓
  [S4] Brute force: 5 bad logins → account locked 5 minutes ✓
  [S5] CSRF: Submit vault action without valid CSRF token → 403 ✓
  [S6] Rate limit: >5 login req/min from same IP → 429 ✓

6. LIMITATIONS
───────────────
  • Python garbage collection does not guarantee immediate memory zeroing.
    Keys derived in memory may persist until GC. A C extension (e.g., libsodium
    via PyNaCl) would provide explicit memory wiping.
  • Without HTTPS, session cookies and file content in transit are vulnerable.
  • No 2FA/MFA currently. Passwords are the only authentication factor.
  • Distributed brute-force (many IPs) bypasses per-IP rate limiting.
  • No virus scanning of uploaded files (intentional: server never decrypts
    unless user authenticates with password).

7. FUTURE IMPROVEMENTS
────────────────────────
  • Add HTTPS enforcement + HSTS header
  • Implement TOTP-based 2FA
  • Add email verification on registration
  • Replace SQLite with PostgreSQL for production
  • Implement Argon2id for password hashing (more memory-hard than bcrypt)
  • WebCrypto API for zero-knowledge client-side encryption
  • File sharing with asymmetric key wrapping (RSA-OAEP or ECDH)
  • Distributed rate limiting with Redis
  • Explicit memory zeroing via ctypes or PyNaCl
"""

if __name__ == "__main__":
    print(THREAT_MODEL)
