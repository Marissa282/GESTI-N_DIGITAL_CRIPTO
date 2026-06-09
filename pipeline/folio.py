"""
pipeline/folio.py — Non-sequential folio generation and checksum validation.

Folio format:  PAC-YY-XXXXXXXX-CC
               ───  ──  ────────  ──
               │    │   │         └─ 2-char base-36 checksum
               │    │   └─────────── 8-char base-36 body (HMAC-derived)
               │    └─────────────── 2-digit year
               └──────────────────── org prefix

Why this design:
  - Non-sequential: the body is HMAC(counter || year, FOLIO_SECRET).
    The counter is never exposed — the folio reveals nothing about
    how many certificates exist or what comes next.
  - Hard to fake: an attacker must guess 8 base-36 chars + pass a
    2-char checksum. Only 1 in 1,296 random guesses passes the checksum
    without ever touching the database.
  - Idempotent: the same (counter, year) always produces the same folio,
    so re-importing a CSV does not create duplicate folios.

Required .env key:
    FOLIO_SECRET — any string, used as HMAC key

Counter strategy:
    The caller provides the counter — typically the total number of
    certificates in the DB at the time of generation.  The counter
    is internal and never printed on the certificate.
"""

import os
import hmac
import hashlib

from dotenv import load_dotenv

load_dotenv()

PREFIX   = "PAC"
BASE36   = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BODY_LEN = 8    # chars for the HMAC-derived body
CHK_LEN  = 2    # chars for the checksum


# ── Helpers ───────────────────────────────────────────────────────────────────

def _folio_secret() -> bytes:
    s = os.getenv("FOLIO_SECRET", "")
    if not s:
        raise EnvironmentError("FOLIO_SECRET is not set in .env")
    return s.encode("utf-8")


def _to_base36(digest_bytes: bytes, length: int) -> str:
    """Convert the first bytes of a digest to a base-36 string of given length."""
    n = int.from_bytes(digest_bytes[:8], "big")
    chars = []
    for _ in range(length):
        chars.append(BASE36[n % 36])
        n //= 36
    return "".join(reversed(chars))


def _hmac_digest(message: str) -> bytes:
    return hmac.new(_folio_secret(), message.encode("utf-8"), hashlib.sha256).digest()


# ── Public API ────────────────────────────────────────────────────────────────

def generate(counter: int, year: int | None = None) -> str:
    """
    Generate a non-sequential folio.

    Args:
        counter : internal sequence number (never exposed in output)
        year    : 4-digit year; defaults to current year

    Returns:
        e.g. "PAC-25-K7M2XQ4B-R4"
    """
    import datetime
    if year is None:
        year = datetime.date.today().year

    yy = str(year)[-2:]         # "2025" → "25"

    # Body: HMAC of "counter:year" — non-sequential, keyed
    body_digest = _hmac_digest(f"{counter}:{yy}")
    body = _to_base36(body_digest, BODY_LEN)

    # Checksum: HMAC of the full body string so far
    full_body  = f"{PREFIX}-{yy}-{body}"
    chk_digest = _hmac_digest(full_body)
    checksum   = _to_base36(chk_digest, CHK_LEN)

    return f"{full_body}-{checksum}"


def validate_checksum(folio: str) -> bool:
    """
    Verify the checksum of a folio without touching the database.

    Returns True if the checksum is valid, False otherwise.
    This is the first gate — reject obviously fake folios instantly.

    >>> validate_checksum("PAC-25-K7M2XQ4B-R4")   # only valid if generated with same secret
    True
    >>> validate_checksum("PAC-25-K7M2XQ4B-XX")
    False
    """
    folio = folio.strip().upper()
    parts = folio.split("-")

    # Expected parts: ["PAC", "YY", "XXXXXXXX", "CC"]
    if len(parts) != 4:
        return False

    prefix, yy, body, checksum = parts

    if prefix != PREFIX:
        return False
    if len(body) != BODY_LEN or len(checksum) != CHK_LEN:
        return False

    # Recompute checksum from the body
    full_body      = f"{PREFIX}-{yy}-{body}"
    chk_digest     = _hmac_digest(full_body)
    expected_chk   = _to_base36(chk_digest, CHK_LEN)

    return checksum == expected_chk


def parse(folio: str) -> dict | None:
    """
    Parse a folio string into its components.
    Returns None if the format is invalid (does not validate checksum).

    >>> parse("PAC-25-K7M2XQ4B-R4")
    {'prefix': 'PAC', 'year': '25', 'body': 'K7M2XQ4B', 'checksum': 'R4'}
    """
    folio = folio.strip().upper()
    parts = folio.split("-")
    if len(parts) != 4:
        return None
    prefix, yy, body, checksum = parts
    return {"prefix": prefix, "year": yy, "body": body, "checksum": checksum}


# ── CLI helper ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        # Validate mode: python folio.py PAC-25-K7M2XQ4B-R4
        f = sys.argv[1]
        ok = validate_checksum(f)
        print(f"  {'VALID' if ok else 'INVALID'}: {f}")
    else:
        # Generate mode: print 5 sample folios
        print("Sample folios (counter 1–5):")
        for i in range(1, 6):
            print(f"  {generate(i)}")
