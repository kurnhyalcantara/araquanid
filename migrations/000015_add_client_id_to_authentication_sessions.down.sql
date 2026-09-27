DROP INDEX IF EXISTS authentication_sessions_identity_client_idx;
ALTER TABLE authentication_sessions DROP COLUMN client_id;
