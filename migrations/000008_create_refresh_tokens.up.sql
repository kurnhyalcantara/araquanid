-- refresh_tokens stores the hash of each issued refresh token and its rotation
-- state within a family (FR-SESSION-003, FR-TOKEN-005). Raw tokens are never
-- stored; only token_hash = SHA-256(raw_token).
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY,
    family_id  UUID        NOT NULL REFERENCES refresh_token_families (id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    status     TEXT        NOT NULL DEFAULT 'ACTIVE',
    client_id  TEXT        NOT NULL,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    issuer_ip  TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
