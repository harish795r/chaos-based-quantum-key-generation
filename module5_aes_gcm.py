"""
Module 5: AES-256-GCM Encryption & Decryption
===============================================
Receives:
  - 256-bit session key  (bytes)  from Module 4 (HKDF)
  - SecurityProfile               from Module 2 (Adaptive Engine)
  - plaintext                     (bytes)

Produces:
  - EncryptedPayload  (nonce + ciphertext + auth tag)

On the receiver side, given the same session key, decrypts and
verifies the authentication tag, recovering the original plaintext.
"""

import os
import time
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import AES

from module2_adaptive_engine import SecurityProfile


# ─────────────────────────────────────────────
# 1.  Data Structures
# ─────────────────────────────────────────────

@dataclass
class EncryptedPayload:
    """
    Everything the receiver needs to decrypt and verify.
    Transmitted over the channel alongside the ciphertext.
    """
    nonce:      bytes   # random IV (12 bytes for GCM)
    ciphertext: bytes   # encrypted data
    auth_tag:   bytes   # GCM authentication tag
    tag_length: int     # in bytes — needed by receiver to init AES-GCM correctly


@dataclass
class EncryptionResult:
    """Full result returned to the caller after encryption."""
    payload:          EncryptedPayload
    plaintext_size:   int     # bytes
    ciphertext_size:  int     # bytes (same as plaintext for GCM — stream cipher mode)
    encryption_time:  float   # seconds
    throughput_mbps:  float   # MB/s


@dataclass
class DecryptionResult:
    """Full result returned to the caller after decryption."""
    plaintext:        bytes
    tag_verified:     bool    # True → integrity confirmed
    decryption_time:  float   # seconds
    throughput_mbps:  float   # MB/s


# ─────────────────────────────────────────────
# 2.  Key Validation Helper
# ─────────────────────────────────────────────

def _validate_session_key(session_key: bytes) -> None:
    """
    AES-256 requires exactly 32 bytes (256 bits).
    If HKDF produced more (e.g., 48 or 64 bytes for MEDIUM/HIGH profiles),
    we use only the first 32 bytes — AES key size is fixed regardless of profile.
    The extra entropy from longer HKDF output is intentional (defense-in-depth);
    the caller should pass the full HKDF output and we slice here.
    """
    if len(session_key) < 32:
        raise ValueError(
            f"Session key too short: got {len(session_key)} bytes, "
            f"need at least 32 bytes for AES-256."
        )


def _extract_aes_key(session_key: bytes) -> bytes:
    """Return the first 32 bytes of the HKDF output as the AES-256 key."""
    return session_key[:32]


# ─────────────────────────────────────────────
# 3.  Encryption
# ─────────────────────────────────────────────

def encrypt(
    plaintext:    bytes,
    session_key:  bytes,
    profile:      SecurityProfile,
    aad:          Optional[bytes] = None,
    verbose:      bool = True,
) -> EncryptionResult:
    """
    Encrypt plaintext using AES-256-GCM.

    Parameters
    ----------
    plaintext    : Raw bytes to encrypt (image, file, message, etc.)
    session_key  : 256-bit (or longer) key from Module 4 HKDF output.
    profile      : SecurityProfile from Module 2 — drives tag & nonce length.
    aad          : Optional Additional Authenticated Data (not encrypted,
                   but integrity-protected). E.g., packet headers.
    verbose      : Print a summary table.

    Returns
    -------
    EncryptionResult
    """
    _validate_session_key(session_key)
    aes_key = _extract_aes_key(session_key)

    # Generate a cryptographically random nonce (IV)
    # GCM standard: 96-bit (12-byte) nonce
    nonce = os.urandom(profile.aes_nonce_length)

    # Initialise AES-GCM cipher
    # mac_len sets the authentication tag length (12, 14, or 16 bytes per profile)
    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=profile.aes_tag_length,
    )

    # Bind AAD to the tag (if provided) — AAD is NOT encrypted
    if aad:
        cipher.update(aad)

    # Encrypt and produce authentication tag in one pass
    t_start = time.perf_counter()
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    t_end = time.perf_counter()

    enc_time = t_end - t_start
    size_mb = len(plaintext) / (1024 ** 2)
    throughput = size_mb / enc_time if enc_time > 0 else float("inf")

    payload = EncryptedPayload(
        nonce=nonce,
        ciphertext=ciphertext,
        auth_tag=auth_tag,
        tag_length=profile.aes_tag_length,
    )

    result = EncryptionResult(
        payload=payload,
        plaintext_size=len(plaintext),
        ciphertext_size=len(ciphertext),
        encryption_time=enc_time,
        throughput_mbps=throughput,
    )

    if verbose:
        _print_encryption_summary(result, profile)

    return result


# ─────────────────────────────────────────────
# 4.  Decryption
# ─────────────────────────────────────────────

def decrypt(
    payload:      EncryptedPayload,
    session_key:  bytes,
    aad:          Optional[bytes] = None,
    verbose:      bool = True,
) -> DecryptionResult:
    """
    Decrypt an EncryptedPayload and verify its authentication tag.

    Parameters
    ----------
    payload      : EncryptedPayload produced by encrypt().
    session_key  : Must be the IDENTICAL session key used during encryption.
                   The receiver regenerates this via the same ML-KEM → chaos → HKDF pipeline.
    aad          : Must match the AAD used during encryption (if any).
    verbose      : Print a summary table.

    Returns
    -------
    DecryptionResult
        .tag_verified = True  → data is authentic and unmodified
        .tag_verified = False → data was tampered (plaintext is b"" in this case)
    """
    _validate_session_key(session_key)
    aes_key = _extract_aes_key(session_key)

    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=payload.nonce,
        mac_len=payload.tag_length,
    )

    if aad:
        cipher.update(aad)

    t_start = time.perf_counter()
    try:
        plaintext = cipher.decrypt_and_verify(payload.ciphertext, payload.auth_tag)
        tag_verified = True
    except ValueError:
        # Authentication tag mismatch → ciphertext was tampered
        plaintext = b""
        tag_verified = False
    t_end = time.perf_counter()

    dec_time = t_end - t_start
    size_mb = len(payload.ciphertext) / (1024 ** 2)
    throughput = size_mb / dec_time if dec_time > 0 else float("inf")

    result = DecryptionResult(
        plaintext=plaintext,
        tag_verified=tag_verified,
        decryption_time=dec_time,
        throughput_mbps=throughput,
    )

    if verbose:
        _print_decryption_summary(result)

    return result


# ─────────────────────────────────────────────
# 5.  Pretty-Print Helpers
# ─────────────────────────────────────────────

def _print_encryption_summary(result: EncryptionResult, profile: SecurityProfile) -> None:
    p = result.payload
    print("\n" + "═" * 55)
    print("   MODULE 5 — AES-256-GCM  ENCRYPTION")
    print("═" * 55)
    print(f"  {'Security Profile':<28} {profile.level}")
    print(f"  {'Plaintext Size':<28} {result.plaintext_size:,} bytes")
    print(f"  {'Ciphertext Size':<28} {result.ciphertext_size:,} bytes")
    print(f"  {'Nonce (hex)':<28} {p.nonce.hex()}")
    print(f"  {'Auth Tag Length':<28} {len(p.auth_tag) * 8} bits")
    print(f"  {'Auth Tag (hex)':<28} {p.auth_tag.hex()}")
    print(f"  {'Ciphertext preview (hex)':<28} {p.ciphertext[:16].hex()} …")
    print(f"  {'Encryption Time':<28} {result.encryption_time * 1000:.4f} ms")
    print(f"  {'Throughput':<28} {result.throughput_mbps:.2f} MB/s")
    print("═" * 55 + "\n")


def _print_decryption_summary(result: DecryptionResult) -> None:
    status = "✅  TAG VERIFIED — data is authentic" if result.tag_verified \
             else "❌  TAG MISMATCH — data was TAMPERED"
    print("\n" + "═" * 55)
    print("   MODULE 5 — AES-256-GCM  DECRYPTION")
    print("═" * 55)
    print(f"  Integrity Check : {status}")
    print(f"  {'Recovered Size':<28} {len(result.plaintext):,} bytes")
    print(f"  {'Decryption Time':<28} {result.decryption_time * 1000:.4f} ms")
    print(f"  {'Throughput':<28} {result.throughput_mbps:.2f} MB/s")
    print("═" * 55 + "\n")
