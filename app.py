"""
app.py — Flask backend for Pasitos Education platform.

Serves index.html and validar.html as static files, plus a JSON API
that the frontend JS calls via fetch().

Endpoints:
    GET  /                           → index.html
    GET  /validar                    → validar.html
    POST /api/login                  → authenticate user
    POST /api/logout                 → clear session
    GET  /api/stats                  → dashboard counts
    GET  /api/participants           → paginated participant list
    GET  /api/participants/<id>      → full participant detail + cert history
    GET  /api/certificates           → paginated certificate list
    GET  /api/certificates/<id>/pdf  → download certificate as PDF
    POST /api/verify                 → verify a folio
    POST /api/import                 → upload XLSX/CSV and run ingest pipeline

Run:
    source venv/bin/activate
    python app.py
    → http://localhost:5000
"""

import os
import sys
import tempfile
from pathlib import Path
from functools import wraps

import bcrypt
from flask import (
    Flask, request, session, jsonify,
    send_from_directory, abort, Response,
)
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))

from db.connection import get_session
from pipeline.crypto import decrypt, encrypt, hmac_curp, cert_hash as make_cert_hash
from pipeline.verify import verify as verify_folio
from pipeline.certificate import generate_pdf
from pipeline.folio import generate as generate_folio
from pipeline import ingest as ingest_module

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = os.getenv("FLASK_SECRET", os.urandom(32))
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024   # 16 MB upload limit


# ── Auth helpers ──────────────────────────────────────────────────────────────

# Role hierarchy: admin > coordinador > capturista
_ROLE_LEVEL = {"admin": 3, "coordinador": 2, "capturista": 1}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "No autenticado"}), 401
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Restrict endpoint to users whose rol is in `roles`."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "No autenticado"}), 401
            if session.get("user_rol") not in roles:
                return jsonify({"error": "Sin permisos para esta acción"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Static pages ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    resp = send_from_directory(".", "index.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/validar")
def validar():
    return send_from_directory(".", "validar.html")


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(force=True)
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email y contraseña requeridos"}), 400

    with get_session() as db:
        row = db.execute(
            text("SELECT id, nombre, password_hash, rol, estado FROM users WHERE email = :e"),
            {"e": email},
        ).fetchone()

    if not row:
        return jsonify({"error": "Credenciales incorrectas"}), 401

    if row.estado != "activo":
        return jsonify({"error": "Cuenta inactiva o bloqueada"}), 403

    if not bcrypt.checkpw(password.encode(), row.password_hash.encode()):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    session["user_id"] = str(row.id)
    session["user_nombre"] = row.nombre
    session["user_rol"] = row.rol

    return jsonify({"nombre": row.nombre, "rol": row.rol})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "nombre": session.get("user_nombre"),
        "rol":    session.get("user_rol"),
    })


# ── User management ───────────────────────────────────────────────────────────

@app.route("/api/users")
@role_required("admin")
def list_users():
    with get_session() as db:
        rows = db.execute(text(
            "SELECT id, nombre, email, rol, estado, created_at FROM users ORDER BY created_at"
        )).fetchall()
    return jsonify([{
        "id":         str(r.id),
        "nombre":     r.nombre,
        "email":      r.email,
        "rol":        r.rol,
        "estado":     r.estado,
        "created_at": str(r.created_at)[:10] if r.created_at else "—",
    } for r in rows])


# ── Dashboard stats ───────────────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def stats():
    with get_session() as db:
        total_participants = db.execute(
            text("SELECT COUNT(*) FROM participants")
        ).scalar() or 0

        total_certs = db.execute(
            text("SELECT COUNT(*) FROM certificates")
        ).scalar() or 0

        emitidos = db.execute(
            text("SELECT COUNT(*) FROM certificates WHERE estado = 'emitido'")
        ).scalar() or 0

        pendientes = db.execute(
            text("SELECT COUNT(*) FROM certificates WHERE estado = 'pendiente'")
        ).scalar() or 0

        # Certificates emitted this month
        nuevos_este_mes = db.execute(
            text("""
                SELECT COUNT(*) FROM certificates
                WHERE estado = 'emitido'
                  AND date_trunc('month', fecha_emision) = date_trunc('month', CURRENT_DATE)
            """)
        ).scalar() or 0

        # Certificates per course (all courses, even those with 0 certs)
        program_rows = db.execute(
            text("""
                SELECT co.code, co.nombre,
                       COUNT(c.id) FILTER (WHERE c.estado = 'emitido') AS emitidos
                FROM courses co
                LEFT JOIN certificates c ON c.course_id = co.id
                WHERE co.estado = 'Activo'
                GROUP BY co.code, co.nombre
                ORDER BY emitidos DESC, co.nombre ASC
            """)
        ).fetchall()

    programs = [
        {"code": r.code, "nombre": r.nombre, "emitidos": r.emitidos or 0}
        for r in program_rows
    ]
    max_emitidos = max((p["emitidos"] for p in programs), default=1) or 1

    return jsonify({
        "participantes":    total_participants,
        "certificados":     total_certs,
        "emitidos":         emitidos,
        "pendientes":       pendientes,
        "nuevos_este_mes":  nuevos_este_mes,
        "programs":         programs,
        "programs_max":     max_emitidos,
    })


# ── Participants ──────────────────────────────────────────────────────────────

@app.route("/api/participants")
@login_required
def participants():
    page        = max(1, int(request.args.get("page", 1)))
    per_page    = int(request.args.get("per_page", 20))
    q           = (request.args.get("q") or "").strip().lower()
    f_cargo     = (request.args.get("cargo") or "").strip()
    f_institucion = (request.args.get("institucion") or "").strip()
    offset      = (page - 1) * per_page

    conditions = []
    params: dict = {"limit": per_page, "offset": offset}

    if q:
        conditions.append("LOWER(p.nombre) LIKE :q")
        params["q"] = f"%{q}%"
    if f_cargo:
        conditions.append("LOWER(p.cargo) = :cargo")
        params["cargo"] = f_cargo.lower()
    if f_institucion:
        conditions.append("LOWER(p.institucion) LIKE :inst")
        params["inst"] = f"%{f_institucion.lower()}%"

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with get_session() as db:
        total = db.execute(
            text(f"SELECT COUNT(*) FROM participants p {where}"),
            params,
        ).scalar() or 0

        rows = db.execute(
            text(f"""
                SELECT p.id, p.nombre, p.curp_enc, p.correo_enc,
                       p.institucion, p.cargo, p.created_at,
                       COUNT(c.id) AS num_certificados,
                       BOOL_OR(c.id IS NOT NULL AND c.edition_id IS NULL) AS needs_group
                FROM participants p
                LEFT JOIN certificates c ON c.participant_id = p.id
                {where}
                GROUP BY p.id
                ORDER BY p.nombre ASC
                LIMIT :limit OFFSET :offset
            """),
            params,
        ).fetchall()

    items = []
    for r in rows:
        items.append({
            "id":           str(r.id),
            "nombre":       r.nombre,
            "curp":         _safe_decrypt(r.curp_enc),
            "correo":       _safe_decrypt(r.correo_enc),
            "institucion":  r.institucion,
            "cargo":        r.cargo,
            "certificados": r.num_certificados,
            "needs_group":  bool(r.needs_group),
            "created_at":   str(r.created_at)[:10],
        })

    # Return distinct cargo/institucion values for filter dropdowns
    with get_session() as db:
        cargos = [row[0] for row in db.execute(
            text("SELECT DISTINCT cargo FROM participants WHERE cargo != 'N/A' ORDER BY cargo")
        ).fetchall()]
        instituciones = [row[0] for row in db.execute(
            text("SELECT DISTINCT institucion FROM participants WHERE institucion != 'N/A' ORDER BY institucion")
        ).fetchall()]

    return jsonify({
        "total": total, "page": page, "per_page": per_page,
        "items": items,
        "filter_cargos": cargos,
        "filter_instituciones": instituciones,
    })


# ── Certificates ──────────────────────────────────────────────────────────────

def _get_programas():
    with get_session() as db:
        return [
            {"code": r.code, "nombre": r.nombre}
            for r in db.execute(
                text("SELECT code, nombre FROM courses WHERE estado='Activo' ORDER BY nombre")
            ).fetchall()
        ]

@app.route("/api/certificates")
@login_required
def certificates():
    page        = max(1, int(request.args.get("page", 1)))
    per_page    = int(request.args.get("per_page", 20))
    q           = (request.args.get("q") or "").strip().lower()
    f_programa  = (request.args.get("programa") or "").strip()
    offset      = (page - 1) * per_page

    conditions = []
    params: dict = {"limit": per_page, "offset": offset}

    if q:
        conditions.append("(LOWER(cert.folio) LIKE :q OR LOWER(p.nombre) LIKE :q)")
        params["q"] = f"%{q}%"
    if f_programa:
        conditions.append("co.code = :programa")
        params["programa"] = f_programa

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with get_session() as db:
        total = db.execute(
            text(f"""
                SELECT COUNT(*)
                FROM certificates cert
                JOIN courses      co ON co.id = cert.course_id
                JOIN participants p  ON p.id  = cert.participant_id
                {where}
            """),
            params,
        ).scalar() or 0

        rows = db.execute(
            text(f"""
                SELECT cert.id, cert.folio, cert.resultado, cert.estado,
                       cert.calificacion, cert.fecha_emision, cert.fecha_inicio,
                       cert.fecha_termino,
                       cert.course_id, cert.edition_id,
                       co.nombre AS curso, co.code AS course_code,
                       p.nombre, p.curp_enc
                FROM certificates cert
                JOIN courses      co ON co.id = cert.course_id
                JOIN participants p  ON p.id  = cert.participant_id
                {where}
                ORDER BY cert.created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            params,
        ).fetchall()

    items = []
    for r in rows:
        items.append({
            "id":           str(r.id),
            "folio":        r.folio or "—",
            "nombre":       r.nombre,
            "curp":         _safe_decrypt(r.curp_enc),
            "curso":        r.curso,
            "course_id":    str(r.course_id),
            "edition_id":   str(r.edition_id) if r.edition_id else None,
            "calificacion": float(r.calificacion) if r.calificacion else None,
            "resultado":    r.resultado,
            "estado":       r.estado,
            "fecha_emision": str(r.fecha_emision) if r.fecha_emision else "—",
            "fecha_inicio":  str(r.fecha_inicio)  if r.fecha_inicio  else "—",
            "fecha_termino": str(r.fecha_termino) if r.fecha_termino else "—",
        })

    return jsonify({"total": total, "page": page, "per_page": per_page, "items": items,
                    "filter_programas": _get_programas()})


# ── Create participant ────────────────────────────────────────────────────────

@app.route("/api/participants", methods=["POST"])
@role_required("admin", "coordinador", "capturista")
def create_participant():
    """Create a new participant from the UI form."""
    import re
    data = request.get_json(force=True)

    nombre     = (data.get("nombre") or "").strip()
    curp       = (data.get("curp") or "").strip().upper()
    fecha_nac  = (data.get("fecha_nac") or "").strip() or None
    correo     = (data.get("correo") or "").strip().lower() or None
    institucion = (data.get("institucion") or "").strip() or "N/A"
    cargo      = (data.get("cargo") or "").strip() or "N/A"

    # ── Validate required fields ──────────────────────────────────────────────
    errors = {}
    if not nombre:
        errors["nombre"] = "El nombre es requerido."
    if not curp:
        errors["curp"] = "La CURP es requerida."
    elif not re.match(r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$", curp):
        errors["curp"] = "Formato de CURP inválido (18 caracteres)."
    if errors:
        return jsonify({"error": "Datos inválidos", "fields": errors}), 422

    ch = hmac_curp(curp)

    with get_session() as db:
        existing = db.execute(
            text("SELECT id FROM participants WHERE curp_hash = :ch"),
            {"ch": ch},
        ).fetchone()
        if existing:
            return jsonify({"error": "Ya existe un participante con esa CURP."}), 409

        row = db.execute(
            text("""
                INSERT INTO participants
                    (curp_hash, curp_enc, fecha_nac_enc, correo_enc, nombre, institucion, cargo)
                VALUES
                    (:ch, :curp_enc, :fecha_nac_enc, :correo_enc, :nombre, :institucion, :cargo)
                RETURNING id
            """),
            {
                "ch":           ch,
                "curp_enc":     encrypt(curp),
                "fecha_nac_enc": encrypt(fecha_nac) if fecha_nac else None,
                "correo_enc":   encrypt(correo) if correo else None,
                "nombre":       nombre,
                "institucion":  institucion,
                "cargo":        cargo,
            },
        ).fetchone()
        db.commit()

    return jsonify({"id": str(row.id), "nombre": nombre}), 201


# ── Participant detail ────────────────────────────────────────────────────────

@app.route("/api/participants/<participant_id>")
@login_required
def participant_detail(participant_id: str):
    """Return full participant info plus their certificate/enrollment history."""
    with get_session() as db:
        p = db.execute(
            text("""
                SELECT id, nombre, curp_enc, fecha_nac_enc, correo_enc,
                       institucion, cargo, created_at
                FROM participants WHERE id = :id
            """),
            {"id": participant_id},
        ).fetchone()
        if not p:
            return jsonify({"error": "Participante no encontrado."}), 404

        certs = db.execute(
            text("""
                SELECT cert.id, cert.folio, cert.resultado, cert.estado,
                       cert.calificacion, cert.fecha_emision,
                       cert.fecha_inicio, cert.fecha_termino,
                       cert.edition_id, cert.course_id,
                       co.nombre AS curso, co.code AS course_code,
                       ed.nombre AS edition_nombre
                FROM certificates cert
                JOIN  courses co         ON co.id = cert.course_id
                LEFT JOIN course_editions ed ON ed.id = cert.edition_id
                WHERE cert.participant_id = :pid
                ORDER BY cert.created_at DESC
            """),
            {"pid": participant_id},
        ).fetchall()

    history = []
    for c in certs:
        history.append({
            "id":              str(c.id),
            "folio":           c.folio or "—",
            "curso":           c.curso,
            "course_id":       str(c.course_id),
            "edition_id":      str(c.edition_id) if c.edition_id else None,
            "edition_nombre":  c.edition_nombre or None,
            "resultado":       c.resultado,
            "estado":          c.estado,
            "calificacion":    float(c.calificacion) if c.calificacion else None,
            "fecha_emision":   str(c.fecha_emision)  if c.fecha_emision  else None,
            "fecha_inicio":    str(c.fecha_inicio)   if c.fecha_inicio   else None,
            "fecha_termino":   str(c.fecha_termino)  if c.fecha_termino  else None,
        })

    return jsonify({
        "id":          str(p.id),
        "nombre":      p.nombre,
        "curp":        _safe_decrypt(p.curp_enc),
        "fecha_nac":   _safe_decrypt(p.fecha_nac_enc) if p.fecha_nac_enc else None,
        "correo":      _safe_decrypt(p.correo_enc),
        "institucion": p.institucion,
        "cargo":       p.cargo,
        "created_at":  str(p.created_at)[:10],
        "certificates": history,
    })


# ── Update participant ────────────────────────────────────────────────────────

@app.route("/api/participants/<participant_id>", methods=["PUT"])
@role_required("admin", "coordinador", "capturista")
def update_participant(participant_id: str):
    """Update editable fields of an existing participant."""
    data = request.get_json(force=True)

    nombre      = (data.get("nombre") or "").strip()
    institucion = (data.get("institucion") or "").strip() or "N/A"
    cargo       = (data.get("cargo") or "").strip() or "N/A"
    fecha_nac   = (data.get("fecha_nac") or "").strip() or None
    correo      = (data.get("correo") or "").strip().lower() or None

    if not nombre:
        return jsonify({"error": "El nombre es requerido.", "fields": {"nombre": "Requerido."}}), 422

    with get_session() as db:
        exists = db.execute(
            text("SELECT id FROM participants WHERE id = :id"),
            {"id": participant_id},
        ).fetchone()
        if not exists:
            return jsonify({"error": "Participante no encontrado."}), 404

        db.execute(
            text("""
                UPDATE participants SET
                    nombre        = :nombre,
                    institucion   = :institucion,
                    cargo         = :cargo,
                    fecha_nac_enc = :fecha_nac_enc,
                    correo_enc    = :correo_enc
                WHERE id = :id
            """),
            {
                "nombre":       nombre,
                "institucion":  institucion,
                "cargo":        cargo,
                "fecha_nac_enc": encrypt(fecha_nac) if fecha_nac else None,
                "correo_enc":   encrypt(correo) if correo else None,
                "id":           participant_id,
            },
        )
        db.commit()

    return jsonify({"ok": True, "nombre": nombre})


# ── Courses & editions ────────────────────────────────────────────────────────

@app.route("/api/courses")
@login_required
def list_courses():
    """List all courses with edition count and enrolled participant count."""
    with get_session() as db:
        rows = db.execute(text("""
            SELECT c.id, c.code, c.nombre, c.horas, c.modalidad, c.estado,
                   c.vigencia_meses,
                   COUNT(DISTINCT cert.id)   AS inscritos,
                   COUNT(DISTINCT ed.id)     AS num_editions
            FROM   courses c
            LEFT JOIN certificates    cert ON cert.course_id = c.id
            LEFT JOIN course_editions ed   ON ed.course_id   = c.id
            GROUP BY c.id
            ORDER BY c.code
        """)).fetchall()
    return jsonify([{
        "id":             str(r.id),
        "code":           r.code,
        "nombre":         r.nombre,
        "horas":          r.horas,
        "modalidad":      r.modalidad,
        "estado":         r.estado,
        "vigencia_meses": r.vigencia_meses,
        "inscritos":      r.inscritos,
        "num_editions":   r.num_editions,
    } for r in rows])


@app.route("/api/courses", methods=["POST"])
@role_required("admin", "coordinador")
def create_course():
    data           = request.get_json(force=True)
    code           = (data.get("code")     or "").strip().upper()
    nombre         = (data.get("nombre")   or "").strip()
    horas          = data.get("horas")
    modalidad      = (data.get("modalidad") or "Presencial").strip()
    vigencia_meses = data.get("vigencia_meses")

    if not code or not nombre:
        return jsonify({"error": "Código y nombre son requeridos"}), 400
    try:
        horas = int(horas)
        if horas <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Horas debe ser un número positivo"}), 400
    if vigencia_meses is not None:
        try:
            vigencia_meses = int(vigencia_meses)
            if vigencia_meses <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "Vigencia debe ser un número de meses positivo"}), 400

    with get_session() as db:
        existing = db.execute(
            text("SELECT id FROM courses WHERE code = :c"), {"c": code}
        ).fetchone()
        if existing:
            return jsonify({"error": f"Ya existe un curso con código {code}"}), 409
        db.execute(text(
            "INSERT INTO courses (code, nombre, horas, modalidad, vigencia_meses) VALUES (:c,:n,:h,:m,:v)"
        ), {"c": code, "n": nombre, "h": horas, "m": modalidad, "v": vigencia_meses})
        db.commit()
    return jsonify({"ok": True, "code": code, "nombre": nombre}), 201


@app.route("/api/courses/<course_id>", methods=["PUT"])
@role_required("admin", "coordinador")
def update_course(course_id):
    data           = request.get_json(force=True)
    vigencia_meses = data.get("vigencia_meses")

    if vigencia_meses is not None and vigencia_meses != "":
        try:
            vigencia_meses = int(vigencia_meses)
            if vigencia_meses <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "Vigencia debe ser un número de meses positivo"}), 400
    else:
        vigencia_meses = None

    with get_session() as db:
        db.execute(text(
            "UPDATE courses SET vigencia_meses = :v WHERE id = :id"
        ), {"v": vigencia_meses, "id": course_id})
        db.commit()
    return jsonify({"ok": True})


@app.route("/api/courses/<course_id>/editions")
@login_required
def list_editions(course_id):
    with get_session() as db:
        rows = db.execute(text("""
            SELECT id, nombre, fecha_inicio, fecha_termino, cupo, estado, created_at
            FROM   course_editions
            WHERE  course_id = :cid
            ORDER BY fecha_inicio DESC
        """), {"cid": course_id}).fetchall()
    return jsonify([{
        "id":            str(r.id),
        "nombre":        r.nombre,
        "fecha_inicio":  str(r.fecha_inicio),
        "fecha_termino": str(r.fecha_termino),
        "cupo":          r.cupo,
        "estado":        r.estado,
    } for r in rows])


@app.route("/api/courses/<course_id>/editions", methods=["POST"])
@role_required("admin", "coordinador")
def create_edition(course_id):
    data          = request.get_json(force=True)
    nombre        = (data.get("nombre")        or "").strip()
    fecha_inicio  = (data.get("fecha_inicio")  or "").strip()
    fecha_termino = (data.get("fecha_termino") or "").strip()
    cupo          = data.get("cupo")

    if not nombre or not fecha_inicio or not fecha_termino:
        return jsonify({"error": "Nombre, fecha de inicio y fecha de término son requeridos"}), 400

    with get_session() as db:
        course = db.execute(
            text("SELECT id FROM courses WHERE id = :id"), {"id": course_id}
        ).fetchone()
        if not course:
            return jsonify({"error": "Curso no encontrado"}), 404
        result = db.execute(text("""
            INSERT INTO course_editions (course_id, nombre, fecha_inicio, fecha_termino, cupo)
            VALUES (:cid, :n, :fi, :ft, :cupo)
            RETURNING id
        """), {
            "cid":  course_id, "n": nombre,
            "fi":   fecha_inicio, "ft": fecha_termino,
            "cupo": int(cupo) if cupo else None,
        })
        new_id = str(result.fetchone()[0])
        db.commit()
    return jsonify({"ok": True, "id": new_id, "nombre": nombre}), 201


@app.route("/api/courses/<course_id>/editions/<edition_id>", methods=["PUT"])
@role_required("admin", "coordinador")
def update_edition(course_id, edition_id):
    data          = request.get_json(force=True)
    nombre        = (data.get("nombre")        or "").strip()
    fecha_inicio  = (data.get("fecha_inicio")  or "").strip()
    fecha_termino = (data.get("fecha_termino") or "").strip()
    cupo          = data.get("cupo")
    estado        = (data.get("estado") or "Activo").strip()

    if not nombre or not fecha_inicio or not fecha_termino:
        return jsonify({"error": "Nombre, fecha de inicio y fecha de término son requeridos"}), 400
    if fecha_termino < fecha_inicio:
        return jsonify({"error": "La fecha de término debe ser igual o posterior al inicio"}), 400

    with get_session() as db:
        result = db.execute(text("""
            UPDATE course_editions
            SET nombre=:n, fecha_inicio=:fi, fecha_termino=:ft, cupo=:cupo, estado=:estado
            WHERE id=:eid AND course_id=:cid
        """), {
            "n": nombre, "fi": fecha_inicio, "ft": fecha_termino,
            "cupo": int(cupo) if cupo else None, "estado": estado,
            "eid": edition_id, "cid": course_id,
        })
        db.commit()
        if result.rowcount == 0:
            return jsonify({"error": "Grupo no encontrado"}), 404
    return jsonify({"ok": True})


@app.route("/api/courses/<course_id>/editions/<edition_id>", methods=["DELETE"])
@role_required("admin", "coordinador")
def delete_edition(course_id, edition_id):
    with get_session() as db:
        # Block if any certificate is linked to this edition
        linked = db.execute(
            text("SELECT COUNT(*) FROM certificates WHERE edition_id = :eid"),
            {"eid": edition_id},
        ).scalar() or 0
        if linked > 0:
            return jsonify({
                "error": f"No se puede eliminar: {linked} certificado(s) están asociados a este grupo. "
                         "Reasigna o elimina esos certificados primero."
            }), 409
        db.execute(text(
            "DELETE FROM course_editions WHERE id=:eid AND course_id=:cid"
        ), {"eid": edition_id, "cid": course_id})
        db.commit()
    return jsonify({"ok": True})


# ── Enroll participant in a course ────────────────────────────────────────────

@app.route("/api/enrollments", methods=["POST"])
@role_required("admin", "coordinador")
def create_enrollment():
    """
    Enroll an existing participant in a course.
    Creates a certificate row; if resultado=Acreditado, generates folio + cert_hash.
    """
    from datetime import date as date_type
    data = request.get_json(force=True)

    participant_id = (data.get("participant_id") or "").strip()
    course_code    = (data.get("course_code") or "").strip().upper()
    edition_id     = (data.get("edition_id") or "").strip() or None
    fecha_inicio   = (data.get("fecha_inicio") or "").strip() or None
    fecha_termino  = (data.get("fecha_termino") or "").strip() or None
    calificacion   = data.get("calificacion")
    resultado      = (data.get("resultado") or "Pendiente").strip()

    errors = {}
    if not participant_id:
        errors["participant_id"] = "Participante requerido."
    if not course_code:
        errors["course_code"] = "Programa requerido."
    if resultado not in ("Acreditado", "No Acreditado", "Pendiente"):
        errors["resultado"] = "Resultado inválido."
    if calificacion is not None:
        try:
            calificacion = float(calificacion)
            if not (0 <= calificacion <= 10):
                errors["calificacion"] = "La calificación debe estar entre 0 y 10."
        except (ValueError, TypeError):
            errors["calificacion"] = "Calificación inválida."
    if errors:
        return jsonify({"error": "Datos inválidos", "fields": errors}), 422

    with get_session() as db:
        # Resolve course
        course_row = db.execute(
            text("SELECT id FROM courses WHERE code = :code"),
            {"code": course_code},
        ).fetchone()
        if not course_row:
            return jsonify({"error": f"Programa '{course_code}' no encontrado."}), 404

        course_id = course_row.id

        # Check duplicate enrollment
        dup = db.execute(
            text("SELECT id FROM certificates WHERE participant_id=:pid AND course_id=:cid"),
            {"pid": participant_id, "cid": course_id},
        ).fetchone()
        if dup:
            return jsonify({"error": "Este participante ya está inscrito en ese programa."}), 409

        # Resolve curp_hash for the integrity hash
        p_row = db.execute(
            text("SELECT curp_hash FROM participants WHERE id = :pid"),
            {"pid": participant_id},
        ).fetchone()
        if not p_row:
            return jsonify({"error": "Participante no encontrado."}), 404

        # If edition selected, auto-fill dates from it
        if edition_id:
            ed_row = db.execute(
                text("SELECT fecha_inicio, fecha_termino FROM course_editions WHERE id = :eid AND course_id = :cid"),
                {"eid": edition_id, "cid": course_id},
            ).fetchone()
            if ed_row:
                fecha_inicio  = str(ed_row.fecha_inicio)
                fecha_termino = str(ed_row.fecha_termino)

        # Generate folio + hash only when Acreditado
        folio         = None
        c_hash        = None
        estado        = "pendiente"
        fecha_emision = None

        if resultado == "Acreditado":
            counter = (db.execute(text("SELECT COUNT(*) FROM certificates")).scalar() or 0) + 1
            folio   = generate_folio(counter)
            # Use fecha_termino as the official emission date; fall back to today
            if fecha_termino:
                try:
                    from datetime import datetime as _dt
                    fecha_emision = _dt.strptime(str(fecha_termino), "%Y-%m-%d").date()
                except ValueError:
                    fecha_emision = date_type.today()
            else:
                fecha_emision = date_type.today()
            c_hash  = make_cert_hash(
                folio         = folio,
                curp_hash_val = p_row.curp_hash,
                course_id     = str(course_id),
                calificacion  = calificacion,
                fecha_emision = str(fecha_emision),
            )
            estado = "emitido"

        cert_row = db.execute(
            text("""
                INSERT INTO certificates
                    (participant_id, course_id, edition_id, folio, fecha_inicio, fecha_termino,
                     calificacion, resultado, estado, fecha_emision, cert_hash, emitido_por)
                VALUES
                    (:pid, :cid, :eid, :folio, :fi, :ft,
                     :cal, :res, :estado, :fem, :chash, :emp)
                RETURNING id, folio
            """),
            {
                "pid":    participant_id,
                "cid":    course_id,
                "eid":    edition_id or None,
                "folio":  folio,
                "fi":     fecha_inicio or None,
                "ft":     fecha_termino or None,
                "cal":    calificacion,
                "res":    resultado,
                "estado": estado,
                "fem":    fecha_emision,
                "chash":  c_hash,
                "emp":    session.get("user_id"),
            },
        ).fetchone()
        db.commit()

    return jsonify({
        "id":        str(cert_row.id),
        "folio":     cert_row.folio or "—",
        "resultado": resultado,
        "estado":    estado,
    }), 201


# ── Update certificate / enrollment ──────────────────────────────────────────

@app.route("/api/certificates/<cert_id>", methods=["PUT"])
@role_required("admin", "coordinador")
def update_certificate(cert_id: str):
    """Update a pendiente/no-acreditado certificate from the UI."""
    from datetime import date as date_type
    data = request.get_json(force=True)

    resultado     = (data.get("resultado") or "").strip() or None
    calificacion  = data.get("calificacion")
    fecha_inicio  = (data.get("fecha_inicio") or "").strip() or None
    fecha_termino = (data.get("fecha_termino") or "").strip() or None
    edition_id    = (data.get("edition_id") or "").strip() or None

    errors = {}
    if resultado and resultado not in ("Acreditado", "No Acreditado", "Pendiente"):
        errors["resultado"] = "Resultado inválido."
    if calificacion is not None and calificacion != "":
        try:
            calificacion = float(calificacion)
            if not (0 <= calificacion <= 10):
                errors["calificacion"] = "La calificación debe estar entre 0 y 10."
        except (ValueError, TypeError):
            errors["calificacion"] = "Calificación inválida."
    else:
        calificacion = None
    if errors:
        return jsonify({"error": "Datos inválidos", "fields": errors}), 422

    with get_session() as db:
        row = db.execute(
            text("""
                SELECT c.id, c.estado, c.resultado, c.calificacion, c.course_id, p.curp_hash
                FROM certificates c
                JOIN participants p ON p.id = c.participant_id
                WHERE c.id = :id
            """),
            {"id": cert_id},
        ).fetchone()

        if not row:
            return jsonify({"error": "Certificado no encontrado."}), 404
        if row.estado in ("emitido", "revocado"):
            return jsonify({"error": "No se puede editar un certificado ya emitido o revocado."}), 409

        # Fall back to current DB values when not provided
        if resultado is None:
            resultado = row.resultado or "Pendiente"
        if calificacion is None and row.calificacion is not None:
            calificacion = float(row.calificacion)

        # If edition selected, pull dates from it
        if edition_id:
            ed = db.execute(
                text("SELECT fecha_inicio, fecha_termino FROM course_editions WHERE id = :eid"),
                {"eid": edition_id},
            ).fetchone()
            if ed:
                fecha_inicio  = str(ed.fecha_inicio)
                fecha_termino = str(ed.fecha_termino)

        folio         = None
        cert_hash_val = None
        estado        = "pendiente"
        fecha_emision = None

        if resultado == "Acreditado":
            counter = (db.execute(text("SELECT COUNT(*) FROM certificates WHERE folio IS NOT NULL")).scalar() or 0) + 1
            folio   = generate_folio(counter)
            # Use fecha_termino from the group if available, otherwise today
            if fecha_termino:
                try:
                    from datetime import datetime as _dt2
                    fecha_emision = _dt2.strptime(str(fecha_termino), "%Y-%m-%d").date()
                except Exception:
                    fecha_emision = date_type.today()
            else:
                fecha_emision = date_type.today()
            cert_hash_val = make_cert_hash(
                folio         = folio,
                curp_hash_val = row.curp_hash,
                course_id     = str(row.course_id),
                calificacion  = calificacion,
                fecha_emision = str(fecha_emision),
            )
            estado = "emitido"

        db.execute(
            text("""
                UPDATE certificates SET
                    resultado     = :res,
                    calificacion  = :cal,
                    edition_id    = COALESCE(:eid, edition_id),
                    fecha_inicio  = COALESCE(:fi, fecha_inicio),
                    fecha_termino = COALESCE(:ft, fecha_termino),
                    estado        = :estado,
                    folio         = COALESCE(:folio, folio),
                    fecha_emision = COALESCE(:fem, fecha_emision),
                    cert_hash     = COALESCE(:ch, cert_hash),
                    emitido_por   = COALESCE(:emp, emitido_por)
                WHERE id = :id
            """),
            {
                "res":    resultado,
                "cal":    calificacion,
                "eid":    edition_id,
                "fi":     fecha_inicio,
                "ft":     fecha_termino,
                "estado": estado,
                "folio":  folio,
                "fem":    fecha_emision,
                "ch":     cert_hash_val,
                "emp":    session.get("user_id") if resultado == "Acreditado" else None,
                "id":     cert_id,
            },
        )
        db.commit()

    return jsonify({"ok": True, "estado": estado, "folio": folio or "—"})


# ── Certificate PDF ────────────────────────────────────────────────────────────

@app.route("/api/certificates/<cert_id>/pdf")
@login_required
def certificate_pdf(cert_id: str):
    """Generate and stream the PDF for a single certificate."""
    try:
        pdf_bytes = generate_pdf(cert_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": f"Error al generar el PDF: {exc}"}), 500

    # Retrieve folio for the filename (best-effort)
    try:
        with get_session() as db:
            folio_row = db.execute(
                text("SELECT folio FROM certificates WHERE id = :id"),
                {"id": cert_id},
            ).fetchone()
        filename = f"{(folio_row.folio or cert_id).replace('/', '-')}.pdf"
    except Exception:
        filename = f"{cert_id}.pdf"

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


# ── Verify ────────────────────────────────────────────────────────────────────

@app.route("/api/verify", methods=["POST"])
def verify():
    """Public endpoint — no login required (anyone can verify a certificate)."""
    data  = request.get_json(force=True)
    folio = (data.get("folio") or "").strip()

    if not folio:
        return jsonify({"valid": False, "message": "Folio requerido"}), 400

    result = verify_folio(folio)

    return jsonify({
        "valid":              result.valid,
        "status":             result.status,
        "message":            result.message,
        "folio":              result.folio,
        "nombre":             result.nombre,
        "curso":              result.curso,
        "calificacion":       result.calificacion,
        "fecha_emision":      result.fecha_emision,
        "fecha_vencimiento":  result.fecha_vencimiento,
        "vigente":            result.vigente,
        "estado":             result.estado,
    })


# ── Import ────────────────────────────────────────────────────────────────────

@app.route("/api/import", methods=["POST"])
@role_required("admin", "coordinador")
def import_file():
    if "file" not in request.files:
        return jsonify({"error": "No se recibió ningún archivo"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Nombre de archivo vacío"}), 400

    suffix = Path(f.filename).suffix.lower()
    if suffix not in (".xlsx", ".xls", ".csv"):
        return jsonify({"error": "Solo se aceptan archivos .xlsx, .xls o .csv"}), 400

    # Save to a temp file so ingest can read it by path
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        # Reset ingest stats before each run
        ingest_module.stats.update({
            "rows_read": 0, "skipped": 0, "participants": 0,
            "certificates": 0, "errors": [],
        })
        ingest_module.run(tmp_path)
        s = ingest_module.stats
        return jsonify({
            "ok":           True,
            "rows_read":    s["rows_read"],
            "skipped":      s["skipped"],
            "participants": s["participants"],
            "certificates": s["certificates"],
            "errors":       s["errors"],
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    finally:
        os.unlink(tmp_path)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_decrypt(val: str | None) -> str:
    try:
        return decrypt(val) or "—"
    except Exception:
        return "—"


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🌐  Pasitos — http://localhost:8000\n")
    app.run(debug=True, port=8000)
