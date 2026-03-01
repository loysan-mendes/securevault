"""
benchmark.py - Cryptographic Performance Benchmark

Measures throughput and latency of SecureVault's cryptographic operations:
  1. PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
  2. AES-256-GCM encryption
  3. AES-256-GCM decryption
  4. End-to-end encrypt+decrypt round-trip

Run with:
    cd securevault_web
    python benchmark.py

Output includes per-operation latency and throughput for different file sizes.

Trade-off Notes:
  - PBKDF2 at 600k iterations takes ~0.5–2s per derivation. This is intentional:
    it means an attacker running an offline dictionary attack can only test
    ~0.5–2 passwords/second per core, vs. millions/second with no stretching.
  - AES-GCM is extremely fast (hardware-accelerated on modern CPUs via AES-NI).
    The bottleneck is always PBKDF2, not AES.
  - For frequent streaming use-cases where re-deriving the key per chunk would
    be too slow, the derived key should be cached in memory for the session
    (future improvement).
"""
import sys
import os
import time
import hashlib
import statistics

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.key_derivation import generate_salt, derive_key
from crypto.encryption import generate_iv, encrypt_data, decrypt_data

SEPARATOR = "─" * 60


def fmt(seconds: float) -> str:
    if seconds < 0.001:
        return f"{seconds*1000000:.1f} µs"
    elif seconds < 1:
        return f"{seconds*1000:.2f} ms"
    else:
        return f"{seconds:.3f} s"


def throughput(size_bytes: int, seconds: float) -> str:
    mb_per_s = (size_bytes / (1024 * 1024)) / seconds
    return f"{mb_per_s:.1f} MB/s"


def benchmark_pbkdf2(iterations: int = 3):
    """Benchmark PBKDF2-HMAC-SHA256 key derivation."""
    print(f"\n{'─'*60}")
    print("PBKDF2-HMAC-SHA256 Key Derivation (600,000 iterations)")
    print(SEPARATOR)

    times = []
    for i in range(iterations):
        salt = generate_salt()
        t0 = time.perf_counter()
        key = derive_key("BenchmarkPassword123!", salt)
        elapsed = time.perf_counter() - t0
        times.append(elapsed)
        print(f"  Run {i+1}: {fmt(elapsed)}")
        del key

    print(f"  Average : {fmt(statistics.mean(times))}")
    print(f"  Std Dev : {fmt(statistics.stdev(times)) if len(times) > 1 else 'N/A'}")
    print(f"  → Attacker rate (offline): ~{1/statistics.mean(times):.1f} guesses/sec/core")
    return statistics.mean(times)


def benchmark_aes_gcm(file_sizes_mb: list, iterations: int = 5):
    """Benchmark AES-256-GCM encryption and decryption for various file sizes."""
    print(f"\n{'─'*60}")
    print("AES-256-GCM Encryption / Decryption")
    print(SEPARATOR)

    # Derive a single key for AES benchmarks (we're not benchmarking PBKDF2 here)
    salt = generate_salt()
    key = derive_key("BenchmarkPassword123!", salt)

    results = []
    for size_mb in file_sizes_mb:
        size_bytes = int(size_mb * 1024 * 1024)
        plaintext = os.urandom(size_bytes)
        aad = b"benchmark_file.bin"

        enc_times = []
        dec_times = []

        for _ in range(iterations):
            iv = generate_iv()

            # Encryption
            t0 = time.perf_counter()
            ciphertext = encrypt_data(plaintext, key, iv, aad)
            enc_times.append(time.perf_counter() - t0)

            # Decryption
            t0 = time.perf_counter()
            recovered = decrypt_data(ciphertext, key, iv, aad)
            dec_times.append(time.perf_counter() - t0)

            assert recovered == plaintext, "Round-trip integrity check FAILED!"

        avg_enc = statistics.mean(enc_times)
        avg_dec = statistics.mean(dec_times)

        print(f"\n  File size: {size_mb:.1f} MB")
        print(f"    Encrypt: avg={fmt(avg_enc)}, throughput={throughput(size_bytes, avg_enc)}")
        print(f"    Decrypt: avg={fmt(avg_dec)}, throughput={throughput(size_bytes, avg_dec)}")
        print(f"    ✓ Round-trip integrity verified (AES-GCM tag OK)")

        results.append({
            "size_mb": size_mb,
            "enc_avg": avg_enc, "dec_avg": avg_dec
        })

    del key
    return results


def benchmark_roundtrip_with_kdf():
    """Full round-trip including PBKDF2 key derivation (real-world scenario)."""
    print(f"\n{'─'*60}")
    print("Full Round-Trip: PBKDF2 → AES-256-GCM Encrypt → Decrypt")
    print(SEPARATOR)

    sizes = [0.001, 0.1, 1.0, 10.0]  # MB
    password = "SecureVaultBenchmark!2024"

    for size_mb in sizes:
        plaintext = os.urandom(int(size_mb * 1024 * 1024))
        aad = b"document.pdf"

        # Upload simulation
        t0 = time.perf_counter()
        upload_salt = generate_salt()
        upload_key  = derive_key(password, upload_salt)
        upload_iv   = generate_iv()
        ciphertext  = encrypt_data(plaintext, upload_key, upload_iv, aad)
        del upload_key
        upload_time = time.perf_counter() - t0

        # Download simulation
        t0 = time.perf_counter()
        dl_key    = derive_key(password, upload_salt)
        recovered = decrypt_data(ciphertext, dl_key, upload_iv, aad)
        del dl_key
        dl_time = time.perf_counter() - t0

        assert recovered == plaintext

        overhead = ((len(ciphertext) - len(plaintext)) / max(len(plaintext), 1)) * 100
        print(f"\n  {size_mb:.3f} MB file:")
        print(f"    Upload (PBKDF2 + AES-GCM encrypt): {fmt(upload_time)}")
        print(f"    Download (PBKDF2 + AES-GCM decrypt): {fmt(dl_time)}")
        print(f"    Ciphertext overhead: +{len(ciphertext)-len(plaintext)} bytes ({overhead:.1f}%) — GCM tag + nonce")


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          SecureVault Cryptographic Benchmark             ║")
    print("╚══════════════════════════════════════════════════════════╝")

    benchmark_pbkdf2(iterations=3)
    benchmark_aes_gcm(file_sizes_mb=[0.1, 1.0, 10.0, 50.0], iterations=5)
    benchmark_roundtrip_with_kdf()

    print(f"\n{'─'*60}")
    print("Design Trade-off Summary:")
    print("  • PBKDF2 (600k iters) is slow BY DESIGN to resist offline brute-force.")
    print("  • AES-256-GCM is fast (hardware AES-NI); bottleneck is always PBKDF2.")
    print("  • GCM adds 16 bytes ciphertext overhead (authentication tag) — negligible.")
    print("  • For files >10MB, PBKDF2 overhead is proportionally smaller.")
    print("  • Future: Cache derived key in encrypted session for multi-upload speed.")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
