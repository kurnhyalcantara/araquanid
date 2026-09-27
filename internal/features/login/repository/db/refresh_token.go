package db

import (
	"context"
	"fmt"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
)

type txRefreshTokens struct{ q querier }

// CreateFamily starts a new refresh-token rotation family for a session
// (FR-SESSION-003).
func (t *txRefreshTokens) CreateFamily(ctx context.Context, familyID, sessionID, identityID string) error {
	_, err := t.q.Exec(ctx, `
		INSERT INTO refresh_token_families (id, session_id, identity_id, status)
		VALUES ($1, $2, $3, 'ACTIVE')`, familyID, sessionID, identityID)
	if err != nil {
		return fmt.Errorf("login/db: create refresh token family: %w", err)
	}
	return nil
}

// CreateToken stores the hash of a newly-issued refresh token (the raw
// token itself is never persisted, FR-SESSION-003).
func (t *txRefreshTokens) CreateToken(ctx context.Context, r repository.RefreshTokenRecord) error {
	_, err := t.q.Exec(ctx, `
		INSERT INTO refresh_tokens (id, family_id, token_hash, status, client_id, issued_at, expires_at, issuer_ip)
		VALUES (gen_random_uuid(), $1, $2, 'ACTIVE', $3, $4, $5, $6)`,
		r.FamilyID, r.TokenHash, r.ClientID, r.IssuedAt, r.ExpiresAt, r.IssuerIP)
	if err != nil {
		return fmt.Errorf("login/db: create refresh token: %w", err)
	}
	return nil
}
