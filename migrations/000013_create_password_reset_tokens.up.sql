-- password_reset_tokens stores forgot-password reset tokens (FR-PWD-006/007).
-- Only the SHA-256 hash of the raw token is stored.
CREATE TABLE password_reset_tokens (
    id           UUID PRIMARY KEY,
    identity_id  UUID        NOT NULL,
    token_hash   TEXT        NOT NULL UNIQUE,
    is_used      BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    requested_ip TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_identity_idx
    ON password_reset_tokens (identity_id);
