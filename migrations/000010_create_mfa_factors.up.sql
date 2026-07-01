-- mfa_factors holds enrolled MFA methods for an identity (FR-MFA-ENROLL/VERIFY).
-- Secrets and keys are stored encrypted / as raw bytes and never returned in
-- cleartext beyond the repository layer.
CREATE TABLE mfa_factors (
    id                    UUID PRIMARY KEY,
    identity_id           UUID        NOT NULL,
    factor_type           TEXT        NOT NULL,
    status                TEXT        NOT NULL DEFAULT 'PENDING',
    display_name          TEXT        NOT NULL DEFAULT '',
    enrolled_at           TIMESTAMPTZ,
    last_used_at          TIMESTAMPTZ,
    -- TOTP time window of the last accepted code, for replay prevention
    -- (FR-MFA-VERIFY-002 step 6).
    last_used_window      BIGINT,
    totp_secret_encrypted BYTEA,
    totp_algorithm        TEXT,
    totp_digits           INT,
    totp_period           INT,
    fido2_credential_id   BYTEA,
    fido2_public_key      BYTEA,
    fido2_aaguid          TEXT,
    fido2_counter         BIGINT      NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mfa_factors_identity_idx ON mfa_factors (identity_id, status);
-- FIDO2 credential ids are globally unique across all identities
-- (FR-MFA-ENROLL-005 step 5).
CREATE UNIQUE INDEX mfa_factors_fido2_credential_id_key
    ON mfa_factors (fido2_credential_id)
    WHERE fido2_credential_id IS NOT NULL;
