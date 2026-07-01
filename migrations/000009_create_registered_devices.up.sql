-- registered_devices tracks devices seen for an identity and their trust state
-- (FR-DEVICE-002). A revoked fingerprint cannot be re-registered (BR-012).
CREATE TABLE registered_devices (
    id                  UUID PRIMARY KEY,
    identity_id         UUID        NOT NULL,
    fingerprint_hash    TEXT        NOT NULL,
    fingerprint_version INT         NOT NULL DEFAULT 1,
    display_name        TEXT        NOT NULL DEFAULT '',
    trust_status        TEXT        NOT NULL DEFAULT 'REGISTERED',
    trust_expires_at    TIMESTAMPTZ,
    registration_ip     TEXT        NOT NULL DEFAULT '',
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (identity_id, fingerprint_hash)
);
