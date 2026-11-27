-- Account security for pgl_auth: token revocation, login lockout, password
-- reset codes and an audit trail. Run once on the Neon database, before the
-- new server version is deployed. Safe to run again.

ALTER TABLE pgl_auth.students
    ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS pgl_auth.login_attempts (
    registration_number TEXT PRIMARY KEY,
    failed_count        INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS pgl_auth.password_reset_codes (
    registration_number TEXT PRIMARY KEY,
    code_hash           TEXT NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    attempts            INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pgl_auth.audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    event               TEXT NOT NULL,
    registration_number TEXT,
    actor               TEXT,
    detail              TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_registration_idx
    ON pgl_auth.audit_log (registration_number, created_at);
