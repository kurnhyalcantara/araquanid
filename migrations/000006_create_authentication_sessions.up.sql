-- authentication_sessions is the session lifecycle store (FR-SESSION-001).
CREATE TABLE authentication_sessions (
    id                   UUID PRIMARY KEY,
    identity_id          UUID        NOT NULL,
    device_id            UUID,
    status               TEXT        NOT NULL DEFAULT 'ACTIVE',
    aal                  TEXT        NOT NULL,
    mfa_factors_used     JSONB       NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    idle_timeout_secs    INT         NOT NULL,
    absolute_expires_at  TIMESTAMPTZ NOT NULL,
    creation_ip          TEXT        NOT NULL DEFAULT '',
    creation_user_agent  TEXT        NOT NULL DEFAULT '',
    revoked_at           TIMESTAMPTZ,
    revoke_reason        TEXT,
    elevated_risk        BOOLEAN     NOT NULL DEFAULT FALSE,
    force_mfa_enrollment BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX authentication_sessions_identity_idx
    ON authentication_sessions (identity_id, status);
CREATE INDEX authentication_sessions_sweep_idx
    ON authentication_sessions (status, absolute_expires_at);
