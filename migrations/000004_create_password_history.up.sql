-- password_history retains prior password hashes for reuse checks (FR-PWD-003).
CREATE TABLE password_history (
    id            UUID PRIMARY KEY,
    credential_id UUID        NOT NULL REFERENCES credentials (id) ON DELETE CASCADE,
    password_hash TEXT        NOT NULL,
    password_salt TEXT        NOT NULL DEFAULT '',
    algorithm     TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX password_history_credential_idx
    ON password_history (credential_id, created_at DESC);
