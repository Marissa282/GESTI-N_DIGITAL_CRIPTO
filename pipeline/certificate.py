"""
pipeline/certificate.py — PDF certificate generation.

Fetches all required fields from the DB, generates a QR code pointing to
the public verification URL, renders the HTML template with Jinja2, and
converts it to a PDF byte-string using WeasyPrint.

Usage (Flask route):
    from pipeline.certificate import generate_pdf
    pdf_bytes = generate_pdf(cert_id)
    return Response(pdf_bytes, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={folio}.pdf"})
"""

import base64
import io
import os
from datetime import date
from pathlib import Path

import qrcode
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import text
from weasyprint import HTML

from db.connection import get_session
from pipeline.crypto import decrypt

# ── Paths ──────────────────────────────────────────────────────────────────────

ROOT       = Path(__file__).parent.parent
TEMPLATE_DIR = ROOT / "templates"
STATIC_DIR   = ROOT / "static"

# ── Verification base URL (override with env var in production) ───────────────

VERIFY_BASE = os.getenv(
    "VERIFY_BASE_URL",
    "http://localhost:8000/validar.html"     # dev default; override in prod
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _qr_data_uri(url: str) -> str:
    """Return a base64 PNG data URI for a QR code pointing to *url*."""
    img = qrcode.make(url, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{encoded}"


def _logo_uri() -> str:
    """Return the Pasitos full-color logo as a base64 data URI (no HTTP)."""
    logo_path = STATIC_DIR / "logo.webp"
    if not logo_path.exists():
        return ""
    encoded = base64.b64encode(logo_path.read_bytes()).decode()
    return f"data:image/webp;base64,{encoded}"


def _fmt_date(value) -> str:
    """Format a date or date-string as '15 de enero de 2025'."""
    if value is None:
        return "—"
    if isinstance(value, str):
        try:
            value = date.fromisoformat(value)
        except ValueError:
            return value
    months = [
        "", "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
    ]
    return f"{value.day} de {months[value.month]} de {value.year}"


def _safe_decrypt(ciphertext: str | None) -> str:
    """Decrypt a field; return '—' on any failure."""
    if not ciphertext:
        return "—"
    try:
        return decrypt(ciphertext) or "—"
    except Exception:
        return "—"


# ── Main function ─────────────────────────────────────────────────────────────

def generate_pdf(cert_id: str) -> bytes:
    """
    Generate a PDF for the certificate with the given UUID.

    Raises:
        ValueError  — certificate not found
        Exception   — propagated from WeasyPrint / Jinja2
    """
    with get_session() as session:
        row = session.execute(
            text("""
                SELECT
                    c.id,
                    c.folio,
                    c.calificacion,
                    c.resultado,
                    c.estado,
                    c.fecha_emision,
                    c.fecha_inicio,
                    c.fecha_termino,
                    co.nombre       AS curso_nombre,
                    co.horas        AS curso_horas,
                    p.nombre        AS participante_nombre,
                    p.curp_enc,
                    p.institucion
                FROM certificates c
                JOIN participants p  ON p.id = c.participant_id
                JOIN courses co      ON co.id = c.course_id
                WHERE c.id = :cert_id
            """),
            {"cert_id": cert_id},
        ).fetchone()

    if not row:
        raise ValueError(f"Certificate {cert_id} not found.")

    folio = row.folio or "—"
    verify_url = f"{VERIFY_BASE}?folio={folio}"

    # Build template context
    context = {
        "nombre":       row.participante_nombre or "—",
        "curp":         _safe_decrypt(row.curp_enc),
        "curso":        row.curso_nombre or "—",
        "institucion":  row.institucion or "—",
        "calificacion": (
            f"{float(row.calificacion):.1f} / 10.0"
            if row.calificacion else "—"
        ),
        "fecha_inicio":  _fmt_date(row.fecha_inicio),
        "fecha_termino": _fmt_date(row.fecha_termino),
        "fecha_emision": _fmt_date(row.fecha_emision),
        "folio":         folio,
        "verify_url":   verify_url,
        "qr_data_uri":  _qr_data_uri(verify_url),
        "logo_path":    _logo_uri(),
    }

    # Render HTML
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("certificate.html")
    html_str = template.render(**context)

    # Convert to PDF
    pdf_bytes = HTML(string=html_str, base_url=str(ROOT)).write_pdf()
    return pdf_bytes
