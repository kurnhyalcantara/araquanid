-- mfa_recovery_codes stores the SHA-256 hash of each single-use recovery code
-- for an MFA factor (FR-MFA-ENROLL-003, FR-MFA-VERIFY-005).
CREATE TABLE mfa_recovery_codes (
    id          UUID PRIMARY KEY,
    factor_id   UUID        NOT NULL REFERENCES mfa_factors (id) ON DELETE CASCADE,
    identity_id UUID        NOT NULL,
    code_hash   TEXT        NOT NULL,
    is_used     BOOLEAN     NOT NULL DEFAULT FALSE,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mfa_recovery_codes_identity_idx
    ON mfa_recovery_codes (identity_id, is_used);
