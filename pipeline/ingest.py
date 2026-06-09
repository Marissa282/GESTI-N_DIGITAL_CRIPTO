"""
pipeline/ingest.py — CSV / Excel import pipeline.

Usage:
    python pipeline/ingest.py                          # uses default xlsx
    python pipeline/ingest.py path/to/file.csv
    python pipeline/ingest.py path/to/file.xlsx

Expected columns (order does not matter — matched by name):
    nombre_completo, curp, fecha_nacimiento, correo,
    institucion, cargo, curso,
    fecha_inicio, fecha_termino, calificacion, resultado

Import behaviour:
    - All records are created with estado=pendiente (NO folio is generated).
    - Folio generation only happens through the UI once a group is assigned
      and the result is set to Acreditado manually.
    - Re-importing the same participant + course: skipped (already exists).
    - Re-importing a participant with a NEW course: a new enrollment is added.
"""

import sys
import os
import re
from datetime import date
from pathlib import Path

import pandas as pd
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).parent.parent))

from db.connection import get_session
from pipeline.crypto import encrypt, hmac_curp

# ── Column name aliases ──────────────────────────────────────────────────────
# Maps any reasonable variation found in CSV headers to our canonical name.

COLUMN_ALIASES = {
    "nombre completo":        "nombre_completo",
    "nombre":                 "nombre_completo",
    "curp":                   "curp",
    "fecha de nacimiento":    "fecha_nacimiento",
    "fecha nacimiento":       "fecha_nacimiento",
    "correo electronico":     "correo",
    "correo electrónico":     "correo",
    "correo":                 "correo",
    "institucion / guarderia":"institucion",
    "institución / guardería":"institucion",
    "institucion":            "institucion",
    "cargo o puesto":         "cargo",
    "cargo":                  "cargo",
    "curso":                  "curso",
    "fecha de inicio":        "fecha_inicio",
    "fecha inicio":           "fecha_inicio",
    "fecha de término":       "fecha_termino",
    "fecha de termino":       "fecha_termino",
    "fecha termino":          "fecha_termino",
    "calificación (0-10)":    "calificacion",
    "calificacion (0-10)":    "calificacion",
    "calificacion":           "calificacion",
    "resultado":              "resultado",
}

CURP_RE = re.compile(r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$")

# ── Stats ─────────────────────────────────────────────────────────────────────

stats = {
    "rows_read":    0,
    "skipped":      0,
    "participants": 0,   # upserted (new or updated)
    "certificates": 0,   # new enrollments added
    "errors":       [],
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _clean(val) -> str | None:
    if val is None or (isinstance(val, float) and __import__("math").isnan(val)):
        return None
    s = str(val).strip()
    return s if s and s.lower() not in ("nan", "none", "n/a", "na") else None


def _parse_date(val) -> date | None:
    if val is None:
        return None
    if isinstance(val, (pd.Timestamp,)):
        return val.date()
    if hasattr(val, "date"):
        return val.date()
    s = str(val).strip()
    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%m/%d/%Y", "%d-%m-%Y"):
        try:
            return pd.to_datetime(s, format=fmt).date()
        except Exception:
            continue
    return None


def _parse_grade(val) -> float | None:
    try:
        g = float(val)
        return round(min(10.0, max(0.0, g)), 2)
    except (TypeError, ValueError):
        return None


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename DataFrame columns to canonical names using COLUMN_ALIASES."""
    renamed = {}
    for col in df.columns:
        key = str(col).strip().lower()
        if key in COLUMN_ALIASES:
            renamed[col] = COLUMN_ALIASES[key]
    return df.rename(columns=renamed)


# ── Load file ─────────────────────────────────────────────────────────────────

def load_file(path: str) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if p.suffix in (".xlsx", ".xls"):
        # The registration sheet has merged header rows — find the real header
        raw = pd.read_excel(path, sheet_name="Registro de Inscripciones",
                            header=None, engine="openpyxl")
        # Row 3 (0-indexed) is the column header row
        raw.columns = raw.iloc[3].tolist()
        df = raw.iloc[4:].reset_index(drop=True)
    else:
        df = pd.read_csv(path)

    return _normalize_columns(df)


# ── Course catalogue seed ─────────────────────────────────────────────────────

def seed_courses_from_catalogue(path: str, session) -> int:
    """
    Read the 'Catálogo de Cursos' sheet and upsert courses into the DB.
    Returns the number of courses inserted/updated.
    """
    try:
        raw = pd.read_excel(path, sheet_name="Catálogo de Cursos",
                            header=None, engine="openpyxl")
    except Exception:
        return 0  # sheet doesn't exist — skip silently

    # Row 2 (0-indexed) is the header row: ID Curso, Nombre del Curso, ...
    raw.columns = raw.iloc[2].tolist()
    df = raw.iloc[3:].reset_index(drop=True)

    count = 0
    for _, row in df.iterrows():
        code   = _clean(row.get("ID Curso"))
        nombre = _clean(row.get("Nombre del Curso"))
        horas  = row.get("Duración (horas)")
        modal  = _clean(row.get("Modalidad")) or "Presencial/Online"
        estado = _clean(row.get("Estado")) or "Activo"

        if not code or not nombre:
            continue

        try:
            horas = int(float(horas)) if horas and str(horas).strip() not in ("", "nan") else None
        except (ValueError, TypeError):
            horas = None

        existing = session.execute(
            text("SELECT id FROM courses WHERE code = :c"),
            {"c": code},
        ).fetchone()

        if existing:
            session.execute(
                text("""
                    UPDATE courses SET nombre=:n, horas=:h, modalidad=:m, estado=:e
                    WHERE code=:c
                """),
                {"n": nombre, "h": horas, "m": modal, "e": estado, "c": code},
            )
        else:
            session.execute(
                text("""
                    INSERT INTO courses (code, nombre, horas, modalidad, estado)
                    VALUES (:c, :n, :h, :m, :e)
                """),
                {"c": code, "n": nombre, "h": horas, "m": modal, "e": estado},
            )
        session.flush()
        count += 1
        print(f"  📚  Course upserted: [{code}] {nombre}")

    return count


# ── Course resolution ─────────────────────────────────────────────────────────

def resolve_course(nombre: str, session) -> str | None:
    """Return course UUID by name (case-insensitive). Auto-creates if missing."""
    row = session.execute(
        text("SELECT id FROM courses WHERE LOWER(nombre) = LOWER(:n)"),
        {"n": nombre},
    ).fetchone()
    if row:
        return str(row[0])

    # Auto-create so the import doesn't fail
    new_id = session.execute(
        text("INSERT INTO courses (code, nombre) VALUES (:code, :nombre) RETURNING id"),
        {"code": f"C-AUTO-{nombre[:6].upper()}", "nombre": nombre},
    ).scalar()
    session.flush()
    print(f"  ⚠  Auto-created course: '{nombre}'")
    return str(new_id)


# ── Participant upsert ────────────────────────────────────────────────────────

def upsert_participant(row: pd.Series, session) -> tuple[str, str] | None:
    """
    Encrypt personal fields, upsert into participants.
    Returns (participant_id, curp_hash) or None on validation failure.
    """
    curp = _clean(row.get("curp"))
    nombre = _clean(row.get("nombre_completo"))

    if not curp or not nombre:
        return None

    curp = curp.upper()
    if not CURP_RE.match(curp):
        print(f"  ⚠  Invalid CURP format: {curp!r} — importing anyway")

    ch = hmac_curp(curp)

    participant_data = {
        "curp_hash":    ch,
        "curp_enc":     encrypt(curp),
        "nombre":       nombre,
        "fecha_nac_enc": encrypt(str(_parse_date(row.get("fecha_nacimiento")) or "")),
        "correo_enc":   encrypt(_clean(row.get("correo"))),
        "institucion":  _clean(row.get("institucion")) or "N/A",
        "cargo":        _clean(row.get("cargo")) or "N/A",
    }

    # Upsert: on conflict (same CURP hash) update plaintext and encrypted fields
    pid = session.execute(
        text("""
            INSERT INTO participants
                (curp_hash, curp_enc, nombre, fecha_nac_enc, correo_enc,
                 institucion, cargo)
            VALUES
                (:curp_hash, :curp_enc, :nombre, :fecha_nac_enc, :correo_enc,
                 :institucion, :cargo)
            ON CONFLICT (curp_hash) DO UPDATE SET
                nombre        = EXCLUDED.nombre,
                fecha_nac_enc = EXCLUDED.fecha_nac_enc,
                correo_enc    = EXCLUDED.correo_enc,
                institucion   = EXCLUDED.institucion,
                cargo         = EXCLUDED.cargo
            RETURNING id
        """),
        participant_data,
    ).scalar()
    session.flush()

    return str(pid), ch


# ── Certificate insert ────────────────────────────────────────────────────────

def insert_certificate(row: pd.Series, participant_id: str,
                       curp_hash: str, course_id: str,
                       session) -> None:
    """Insert one certificate row as Pendiente. Folio is never generated here."""
    calificacion  = _parse_grade(row.get("calificacion"))
    resultado     = _clean(row.get("resultado")) or "Pendiente"
    fecha_inicio  = _parse_date(row.get("fecha_inicio"))
    fecha_termino = _parse_date(row.get("fecha_termino"))

    # Check if a certificate row already exists for this participant+course
    existing = session.execute(
        text("SELECT id, estado FROM certificates WHERE participant_id=:p AND course_id=:c"),
        {"p": participant_id, "c": course_id},
    ).fetchone()

    if existing:
        # Never overwrite an existing record (emitido, pendiente, or revocado)
        return

    # Always insert as pendiente — no folio, no hash
    session.execute(
        text("""
            INSERT INTO certificates
                (participant_id, course_id, fecha_inicio, fecha_termino,
                 calificacion, resultado, estado)
            VALUES
                (:pid, :cid, :fi, :ft,
                 :cal, :res, 'pendiente')
        """),
        {
            "pid": participant_id,
            "cid": course_id,
            "fi":  fecha_inicio,
            "ft":  fecha_termino,
            "cal": calificacion,
            "res": resultado,
        },
    )
    session.flush()
    stats["certificates"] += 1


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run(path: str) -> None:
    print(f"\n📂  Loading: {path}")
    df = load_file(path)
    stats["rows_read"] = len(df)

    with get_session() as session:
        # Seed courses from catalogue sheet first (XLSX only)
        if path.lower().endswith((".xlsx", ".xls")):
            n = seed_courses_from_catalogue(path, session)
            if n:
                session.commit()
                print(f"  ✅  {n} course(s) upserted from catalogue\n")
        for idx, row in df.iterrows():
            curp_raw = _clean(row.get("curp"))
            nombre_raw = _clean(row.get("nombre_completo"))
            curso_raw  = _clean(row.get("curso"))

            if not curp_raw or not nombre_raw or not curso_raw:
                stats["skipped"] += 1
                continue

            try:
                result = upsert_participant(row, session)
                if not result:
                    stats["skipped"] += 1
                    continue

                participant_id, curp_hash = result
                stats["participants"] += 1
                print(f"  👤  {nombre_raw} ({curp_raw.upper()})")

                course_id = resolve_course(curso_raw, session)
                insert_certificate(row, participant_id, curp_hash, course_id, session)

                session.commit()

            except Exception as exc:
                session.rollback()
                msg = f"Row {idx} ({curp_raw}): {exc}"
                stats["errors"].append(msg)
                print(f"  ❌  {msg}")

    _print_summary()


def _print_summary() -> None:
    print("\n" + "═" * 50)
    print("  IMPORT SUMMARY")
    print("═" * 50)
    print(f"  Rows read:      {stats['rows_read']}")
    print(f"  Skipped:        {stats['skipped']}")
    print(f"  Participants:   {stats['participants']} upserted (new or updated)")
    print(f"  Enrollments:    {stats['certificates']} new (all as Pendiente)")
    print(f"  Note: folios are generated from the UI after assigning a group.")
    if stats["errors"]:
        print(f"  Errors ({len(stats['errors'])}):")
        for e in stats["errors"]:
            print(f"    - {e}")
    print("═" * 50 + "\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    default = Path(__file__).parent.parent / "Pasitos Registro Cursos v0.xlsx"
    target  = sys.argv[1] if len(sys.argv) > 1 else str(default)
    run(target)
