"""
pipeline/verify.py — Certificate verification by folio.

Three-step verification (each step is a harder gate):

  Step 1 — Checksum (no DB hit)
    Recompute the 2-char checksum from the folio body.
    Rejects obviously fake folios immediately.
    Only 1 in 1,296 random strings passes this gate.

  Step 2 — Database lookup
    Query certificates WHERE folio = input.
    Rejects folios that were never issued.

  Step 3 — Integrity hash
    Recompute cert_hash from the stored row data.
    Detects in-DB tampering (someone editing a grade directly in Postgres).

If all three pass: decrypt participant fields and return the full result.
The result also includes expiry info derived from courses.vigencia_meses.

Usage:
    python pipeline/verify.py PAC-25-K7M2XQ4B-R4
    
    Or import and call verify() from application code.
"""

import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from dateutil.relativedelta import relativedelta

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).parent.parent))

from db.connection import get_session
from pipeline.folio import validate_checksum
from pipeline.crypto import decrypt, cert_hash as make_cert_hash


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    valid:       bool
    status:      str      # "valid" | "vencido" | "invalid_checksum" | "not_found" | "tampered" | "revocado"
    message:     str
    # Populated when valid=True or status="vencido"
    folio:            str   | None = None
    nombre:           str   | None = None
    curso:            str   | None = None
    calificacion:     float | None = None
    fecha_emision:    str   | None = None
    fecha_vencimiento: str  | None = None   # None = no expiry
    estado:           str   | None = None
    vigente:          bool  | None = None   # True = vigente, False = vencido, None = sin vigencia definida


# ── Expiry helper ─────────────────────────────────────────────────────────────

def _compute_expiry(fecha_emision_val, vigencia_meses) -> tuple[str | None, bool | None]:
    """
    Returns (fecha_vencimiento_str, vigente_bool).
    If vigencia_meses is None: returns (None, None) — no expiry defined.
    """
    if not vigencia_meses or not fecha_emision_val:
        return None, None
    try:
        if isinstance(fecha_emision_val, str):
            emision = date.fromisoformat(fecha_emision_val)
        else:
            emision = fecha_emision_val
        vencimiento = emision + relativedelta(months=int(vigencia_meses))
        vigente     = date.today() <= vencimiento
        return str(vencimiento), vigente
    except Exception:
        return None, None


# ── Main verification function ────────────────────────────────────────────────

def verify(folio_input: str) -> VerifyResult:
    """
    Verify a certificate folio. Returns a VerifyResult.

    This function is safe to call from a web endpoint —
    it never raises, always returns a structured result.
    """
    folio = folio_input.strip().upper()

    # ── Step 1: Checksum (no DB) ──────────────────────────────────────────────
    if not validate_checksum(folio):
        return VerifyResult(
            valid=False,
            status="invalid_checksum",
            message="El folio no tiene un formato válido.",
        )

    with get_session() as session:

        # ── Step 2: DB lookup ─────────────────────────────────────────────────
        row = session.execute(
            text("""
                SELECT
                    c.id,
                    c.folio,
                    c.calificacion,
                    c.resultado,
                    c.estado,
                    c.fecha_emision,
                    c.cert_hash,
                    c.course_id,
                    co.nombre         AS curso_nombre,
                    co.vigencia_meses AS vigencia_meses,
                    p.curp_hash,
                    p.nombre
                FROM certificates c
                JOIN participants p  ON p.id = c.participant_id
                JOIN courses co      ON co.id = c.course_id
                WHERE c.folio = :folio
            """),
            {"folio": folio},
        ).fetchone()

        if not row:
            return VerifyResult(
                valid=False,
                status="not_found",
                message="El folio no existe en nuestra base de datos.",
            )

        # ── Step 3: Integrity hash ────────────────────────────────────────────
        expected_hash = make_cert_hash(
            folio         = row.folio,
            curp_hash_val = row.curp_hash,
            course_id     = str(row.course_id),
            calificacion  = float(row.calificacion) if row.calificacion else None,
            fecha_emision = str(row.fecha_emision),
        )

        if row.cert_hash != expected_hash:
            return VerifyResult(
                valid=False,
                status="tampered",
                message="⚠️  La integridad del certificado no pudo ser verificada. "
                        "Contacte a Pasitos Education & Health A.C.",
            )

        # ── Revocation check ──────────────────────────────────────────────────
        if row.estado == "revocado":
            return VerifyResult(
                valid=False,
                status="revocado",
                message="Este certificado ha sido revocado.",
                folio=folio,
                estado="revocado",
            )

        # ── Expiry check ──────────────────────────────────────────────────────
        fecha_vencimiento, vigente = _compute_expiry(row.fecha_emision, row.vigencia_meses)
        nombre = row.nombre or "—"

        if vigente is False:
            # Certificate exists and is authentic but has expired
            return VerifyResult(
                valid=False,
                status="vencido",
                message="Este certificado existe y fue emitido correctamente, pero ya no está vigente.",
                folio=folio,
                nombre=nombre,
                curso=row.curso_nombre,
                calificacion=float(row.calificacion) if row.calificacion else None,
                fecha_emision=str(row.fecha_emision) if row.fecha_emision else None,
                fecha_vencimiento=fecha_vencimiento,
                estado=row.estado,
                vigente=False,
            )

        # ── All checks passed — return result ────────────────────────────────
        return VerifyResult(
            valid=True,
            status="valid",
            message="Certificado válido y auténtico.",
            folio=folio,
            nombre=nombre,
            curso=row.curso_nombre,
            calificacion=float(row.calificacion) if row.calificacion else None,
            fecha_emision=str(row.fecha_emision) if row.fecha_emision else None,
            fecha_vencimiento=fecha_vencimiento,
            estado=row.estado,
            vigente=True if vigente else None,
        )


# ── Pretty-print helper ───────────────────────────────────────────────────────

def _print_result(r: VerifyResult) -> None:
    line = "═" * 52
    print(f"\n{line}")
    if r.valid:
        print("  ✅  CERTIFICADO VÁLIDO")
        print(f"{line}")
        print(f"  Folio:       {r.folio}")
        print(f"  Titular:     {r.nombre}")
        print(f"  Programa:    {r.curso}")
        print(f"  Calificación:{r.calificacion}")
        print(f"  Emisión:     {r.fecha_emision}")
        print(f"  Vencimiento: {r.fecha_vencimiento or 'Sin vigencia definida'}")
        print(f"  Estado:      {r.estado}")
    elif r.status == "vencido":
        print("  ⚠️   CERTIFICADO VENCIDO (auténtico pero fuera de vigencia)")
        print(f"{line}")
        print(f"  Folio:       {r.folio}")
        print(f"  Titular:     {r.nombre}")
        print(f"  Programa:    {r.curso}")
        print(f"  Emisión:     {r.fecha_emision}")
        print(f"  Venció:      {r.fecha_vencimiento}")
    else:
        print(f"  ❌  {r.message}")
        print(f"  Status: {r.status}")
    print(f"{line}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pipeline/verify.py <FOLIO>")
        print("Example: python pipeline/verify.py PAC-25-K7M2XQ4B-R4")
        sys.exit(1)

    result = verify(sys.argv[1])
    _print_result(result)
    sys.exit(0 if result.valid else 1)

