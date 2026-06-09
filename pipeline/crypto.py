"""
pipeline/crypto.py — Field-level encryption and HMAC helpers.

Encryption:  AES-256-GCM via the `cryptography` library.
             Each call to encrypt() produces a unique nonce, so the same
             plaintext never produces the same ciphertext.

Storage format (hex string in DB):
    [12-byte nonce][ciphertext][16-byte GCM tag]
    All concatenated and hex-encoded → one opaque TEXT column.

HMAC:        HMAC-SHA256 used for the searchable CURP index.
             Deterministic: same input always produces the same digest,
             so we can do WHERE curp_hash = hmac(curp) without exposing
             the actual CURP.

Required .env keys:
    ENCRYPTION_KEY  — 64 hex chars (32 bytes) for AES-256
    HMAC_SECRET     — any string, used as HMAC key for curp_hash
"""

import os
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()


# ── Key loading ───────────────────────────────────────────────────────────────

def _load_aes_key() -> bytes:
    raw = os.getenv("ENCRYPTION_KEY", "")
    if len(raw) != 64:
        raise EnvironmentError(
            "ENCRYPTION_KEY must be 64 hex chars (32 bytes). "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return bytes.fromhex(raw)


def _load_hmac_secret() -> bytes:
    raw = os.getenv("HMAC_SECRET", "")
    if not raw:
        raise EnvironmentError("HMAC_SECRET is not set in .env")
    return raw.encode("utf-8")


# ── AES-256-GCM encrypt / decrypt ─────────────────────────────────────────────

def encrypt(plaintext: str | None) -> str | None:
    """
    Encrypt a plaintext string with AES-256-GCM.

    Returns a hex string:  nonce(12B) + ciphertext + tag(16B)
    Returns None if plaintext is None or empty.
    """
    if not plaintext:
        return None

    key   = _load_aes_key()
    nonce = os.urandom(12)          # unique per call — never reuse
    aesgcm = AESGCM(key)

    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return (nonce + ciphertext_with_tag).hex()


def decrypt(stored: str | None) -> str | None:
    """
    Decrypt a hex string produced by encrypt().

    Returns the original plaintext, or None if stored is None/empty.
    Raises ValueError if the ciphertext has been tampered with
    (GCM authentication tag mismatch).
    """
    if not stored:
        return None

    key    = _load_aes_key()
    raw    = bytes.fromhex(stored)
    nonce  = raw[:12]
    ciphertext_with_tag = raw[12:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None).decode("utf-8")


# ── HMAC — searchable CURP index ──────────────────────────────────────────────

def hmac_curp(curp: str) -> str:
    """
    Compute a deterministic HMAC-SHA256 of the CURP.

    Stored as curp_hash in the participants table.
    Used for lookup: WHERE curp_hash = hmac_curp(input_curp)
    Reveals nothing about the CURP without HMAC_SECRET.
    """
    secret = _load_hmac_secret()
    return hmac.new(secret, curp.upper().strip().encode("utf-8"), hashlib.sha256).hexdigest()


# ── Certificate integrity hash ────────────────────────────────────────────────

def cert_hash(folio: str, curp_hash_val: str, course_id: str,
              calificacion: float | None, fecha_emision: str) -> str:
    """
    SHA-256 fingerprint for tamper detection.

    Built from the core certificate fields + CERT_SECRET.
    If any field changes in the DB, this hash will no longer match.

    Args:
        folio          : certificate folio  (e.g. "PAC-25-K7M2XQ4B-R4")
        curp_hash_val  : the stored curp_hash of the participant
        course_id      : UUID string of the course row
        calificacion   : final grade as float (or None)
        fecha_emision  : ISO date string (e.g. "2025-03-28")
    """
    secret = os.getenv("CERT_SECRET", "")
    if not secret:
        raise EnvironmentError("CERT_SECRET is not set in .env")

    payload = "|".join([
        folio.upper().strip(),
        curp_hash_val,
        str(course_id),
        str(calificacion) if calificacion is not None else "",
        str(fecha_emision),
        secret,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Utility: generate .env keys ───────────────────────────────────────────────

def generate_keys():
    """Print fresh random keys suitable for .env — run once during setup."""
    import secrets
    print("# Paste these into your .env file:")
    print(f"ENCRYPTION_KEY={secrets.token_hex(32)}")
    print(f"HMAC_SECRET={secrets.token_hex(32)}")
    print(f"CERT_SECRET={secrets.token_hex(32)}")
    print(f"FOLIO_SECRET={secrets.token_hex(32)}")


if __name__ == "__main__":
    generate_keys()
