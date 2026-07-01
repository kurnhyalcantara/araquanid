-- mfa_pending_otps holds one-time passwords awaiting verification
-- (FR-MFA-VERIFY-003, FR-MFA-ENROLL-007). Only the SHA-256 hash is stored.
CREATE TABLE mfa_pending_otps (
    id            UUID PRIMARY KEY,
    identity_id   UUID        NOT NULL,
    otp_hash      TEXT        NOT NULL,
    purpose       TEXT        NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    attempt_count INT         NOT NULL DEFAULT 0,
    is_used       BOOLEAN     NOT NULL DEFAULT FALSE,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mfa_pending_otps_lookup_idx
    ON mfa_pending_otps (identity_id, purpose, is_used);
