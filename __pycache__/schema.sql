-- ═══════════════════════════════════════════════════════════════════════════
-- Pasitos Education & Health A.C. — Database Schema v2
-- PostgreSQL (Supabase-compatible)
--
-- Run:  psql $DATABASE_URL -f db/schema.sql
--       or paste into Supabase → SQL Editor
--
-- Design principles:
--   - Only fields that auto-populate from CSV or are auto-generated
--   - Personal data stored AES-256-GCM encrypted; CURP searchable via HMAC
--   - Single folio field (non-sequential, checksum-validated)
--   - SHA-256 cert_hash for tamper detection
-- ═══════════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Drop in reverse dependency order if re-running
DROP TABLE IF EXISTS certificates  CASCADE;
DROP TABLE IF EXISTS course_editions CASCADE;
DROP TABLE IF EXISTS participants   CASCADE;
DROP TABLE IF EXISTS courses        CASCADE;
DROP TABLE IF EXISTS users          CASCADE;


-- ── 1. USERS ─────────────────────────────────────────────────────────────────
-- Staff who log into the platform.  NOT participants.
-- Roles control access: admin | coordinador | capturista

CREATE TABLE users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    nombre        TEXT        NOT NULL,
    email         TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,          -- bcrypt, never plaintext
    rol           TEXT        NOT NULL DEFAULT 'capturista'
                              CHECK (rol IN ('admin', 'coordinador', 'capturista')),
    estado        TEXT        NOT NULL DEFAULT 'activo'
                              CHECK (estado IN ('activo', 'inactivo', 'bloqueado')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ── 2. COURSES ────────────────────────────────────────────────────────────────
-- Catalog of programs offered by Pasitos.
-- Populated from the "Catálogo de Cursos" sheet or CSV.

CREATE TABLE courses (
    id             UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    code           TEXT    NOT NULL UNIQUE,        -- e.g. "C-001"
    nombre         TEXT    NOT NULL,               -- e.g. "Puericultura"
    horas          INTEGER CHECK (horas > 0),      -- required for DC-3
    modalidad      TEXT    DEFAULT 'Presencial/Online',
    vigencia_meses INTEGER CHECK (vigencia_meses > 0),  -- NULL = sin vencimiento
    estado         TEXT    NOT NULL DEFAULT 'Activo'
                           CHECK (estado IN ('Activo', 'Inactivo'))
);


-- ── 3. PARTICIPANTS ───────────────────────────────────────────────────────────
-- One row per real person.
--
-- Sensitive fields are AES-256-GCM encrypted by the application layer.
-- The DB stores opaque hex blobs — unreadable without the ENCRYPTION_KEY.
--
-- curp_hash = HMAC-SHA256(curp, HMAC_SECRET)
--   → stored plaintext so we can do: WHERE curp_hash = ?
--   → reveals nothing about the actual CURP without the secret
--
-- nombre is stored plaintext — a name alone is not sensitive and must be
-- searchable.  Only CURP, DOB, and email are truly sensitive identifiers.

CREATE TABLE participants (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Searchable index (HMAC of CURP — not the CURP itself)
    curp_hash    TEXT        NOT NULL UNIQUE,

    -- Encrypted sensitive data (AES-256-GCM, hex-encoded nonce+ciphertext)
    curp_enc      TEXT        NOT NULL,
    fecha_nac_enc TEXT,
    correo_enc    TEXT,

    -- Plaintext fields — searchable, not sensitive on their own
    nombre      TEXT        NOT NULL,
    institucion TEXT        NOT NULL DEFAULT 'N/A',
    cargo       TEXT        NOT NULL DEFAULT 'N/A',

    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_participants_curp_hash ON participants (curp_hash);


-- ── 4. COURSE EDITIONS ────────────────────────────────────────────────────────
-- Scheduled groups/sessions for each course.
-- A course (e.g. "Puericultura") can run multiple times a year.
-- When enrolling a participant, the user picks an edition and dates auto-fill.

CREATE TABLE course_editions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id     UUID        NOT NULL REFERENCES courses (id) ON DELETE RESTRICT,
    nombre        TEXT        NOT NULL,   -- e.g. "Generación Enero 2026"
    fecha_inicio  DATE        NOT NULL,
    fecha_termino DATE        NOT NULL,
    cupo          INTEGER     CHECK (cupo > 0),
    estado        TEXT        NOT NULL DEFAULT 'Activo'
                              CHECK (estado IN ('Activo', 'Cerrado', 'Cancelado')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (fecha_termino >= fecha_inicio)
);

CREATE INDEX idx_course_editions_course_id ON course_editions (course_id);


-- ── 5. CERTIFICATES ───────────────────────────────────────────────────────────
-- One row per enrollment.  Merges enrollment + certificate into a single table.
--
-- Folio format:  PAC-YY-XXXXXXXX-CC
--   PAC        → org prefix
--   YY         → 2-digit year
--   XXXXXXXX   → 8 base-36 chars derived from HMAC(internal_counter, FOLIO_SECRET)
--   CC         → 2 base-36 checksum chars, HMAC(body, FOLIO_SECRET)[:2]
--
-- cert_hash = SHA-256(folio + curp_hash + course_id + calificacion + fecha_emision + CERT_SECRET)
--   → detects tampering with any core field

CREATE TABLE certificates (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    participant_id UUID         NOT NULL REFERENCES participants (id) ON DELETE RESTRICT,
    course_id      UUID         NOT NULL REFERENCES courses (id)      ON DELETE RESTRICT,
    edition_id     UUID                  REFERENCES course_editions (id) ON DELETE SET NULL,

    -- Auto-generated on import when resultado = Acreditado
    folio          TEXT         UNIQUE,       -- NULL until emitido

    -- Fields that come directly from the CSV row
    fecha_inicio   DATE,
    fecha_termino  DATE,
    calificacion   NUMERIC(4,2) CHECK (calificacion BETWEEN 0 AND 10),
    resultado      TEXT         NOT NULL DEFAULT 'Pendiente'
                                CHECK (resultado IN ('Acreditado', 'No Acreditado', 'Pendiente')),

    -- Lifecycle
    estado         TEXT         NOT NULL DEFAULT 'pendiente'
                                CHECK (estado IN ('emitido', 'revocado', 'pendiente')),
    fecha_emision  DATE,                      -- set when estado → emitido

    -- Integrity fingerprint (set on emit, verified on lookup)
    cert_hash      TEXT,

    -- Who issued it (nullable — set when emitido)
    emitido_por    UUID         REFERENCES users (id),

    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- One enrollment per person per course
    UNIQUE (participant_id, course_id)
);

CREATE INDEX idx_certificates_folio          ON certificates (folio);
CREATE INDEX idx_certificates_participant_id ON certificates (participant_id);


-- ═══════════════════════════════════════════════════════════════════════════
-- ENTITY RELATIONSHIP
--
--   users ──────────────────────────────────────────── (emitido_por)
--                                                           │
--   participants (curp_hash + encrypted fields) ──► certificates ◄── courses
-- ═══════════════════════════════════════════════════════════════════════════
