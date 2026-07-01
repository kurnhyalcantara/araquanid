-- credentials holds the password and lockout state for an identity
-- (FR-LOGIN-004/005/009, FR-PWD-004). One row per identity.
CREATE TABLE credentials (
    id                    UUID PRIMARY KEY,
    identity_id           UUID        NOT NULL UNIQUE,
    password_hash         TEXT        NOT NULL,
    password_algorithm    TEXT        NOT NULL DEFAULT 'argon2id',
    password_version      INT         NOT NULL DEFAULT 1,
    password_created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    password_expires_at   TIMESTAMPTZ,
    force_password_change BOOLEAN     NOT NULL DEFAULT FALSE,
    failed_attempt_count  INT         NOT NULL DEFAULT 0,
    last_failed_at        TIMESTAMPTZ,
    lockout_status        TEXT        NOT NULL DEFAULT 'UNLOCKED',
    locked_at             TIMESTAMPTZ,
    locked_until          TIMESTAMPTZ,
    -- Cumulative lifetime lockout counter; never reset (FR-LOGIN-009).
    lockout_history_count INT         NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
