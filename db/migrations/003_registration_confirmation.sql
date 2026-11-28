-- Registration waits for an e-mail confirmation before the account is created.
-- Run once on the Neon database before deploying the new server version.
-- Safe to run again.

CREATE TABLE IF NOT EXISTS pgl_auth.pending_registrations (
    registration_number TEXT PRIMARY KEY,
    email               TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    token_hash          TEXT NOT NULL UNIQUE,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
