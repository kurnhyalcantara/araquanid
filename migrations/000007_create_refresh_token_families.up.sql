-- refresh_token_families groups the rotating refresh tokens of one session so a
-- detected reuse can compromise the whole family (FR-SESSION-003, FR-TOKEN-005).
CREATE TABLE refresh_token_families (
    id          UUID PRIMARY KEY,
    session_id  UUID        NOT NULL REFERENCES authentication_sessions (id) ON DELETE CASCADE,
    identity_id UUID        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'ACTIVE',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX refresh_token_families_session_idx
    ON refresh_token_families (session_id);
