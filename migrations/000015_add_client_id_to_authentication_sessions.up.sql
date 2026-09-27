-- authentication_sessions was missing the calling-client dimension that
-- FR-LOGIN-012's concurrent session policy scopes by ("count active
-- sessions for identity + client_id"). Nullable/defaulted so existing rows
-- (none expected pre-feature, but kept safe) don't need backfilling.
ALTER TABLE authentication_sessions
    ADD COLUMN client_id TEXT NOT NULL DEFAULT '';

CREATE INDEX authentication_sessions_identity_client_idx
    ON authentication_sessions (identity_id, client_id, status);
