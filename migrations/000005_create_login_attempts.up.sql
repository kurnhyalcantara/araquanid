-- login_attempts is the append-only audit trail of authentication attempts
-- (FR-POST-AUTH-001, §15.2). This table is INSERT-only: application database
-- roles SHALL NOT hold UPDATE or DELETE privileges on it.
CREATE TABLE login_attempts (
    id                 UUID PRIMARY KEY,
    identity_id        UUID,
    identifier_hash    TEXT        NOT NULL,
    outcome            TEXT        NOT NULL,
    failure_reason     TEXT        NOT NULL DEFAULT '',
    ip_address         TEXT        NOT NULL DEFAULT '',
    user_agent         TEXT        NOT NULL DEFAULT '',
    device_fingerprint TEXT,
    attempted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    session_id         UUID,
    mfa_factor_type    TEXT
);
CREATE INDEX login_attempts_identity_idx
    ON login_attempts (identity_id, attempted_at DESC);
CREATE INDEX login_attempts_identifier_idx
    ON login_attempts (identifier_hash, attempted_at DESC);
