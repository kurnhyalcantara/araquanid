package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	domain_auth "github.com/kurnhyalcantara/araquanid/internal/domain/auth"
)

type loginAttemptRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresLoginAttemptRepository returns the PostgreSQL-backed, append-only login
// attempt audit repository.
func NewPostgresLoginAttemptRepository(pool *pgxpool.Pool) domain_auth.LoginAttemptRepository {
	return &loginAttemptRepository{pool: pool}
}

func (r *loginAttemptRepository) Create(ctx context.Context, a *domain_auth.LoginAttempt) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO login_attempts
			(id, identity_id, identifier_hash, outcome, failure_reason, ip_address,
			 user_agent, device_fingerprint, attempted_at, session_id, mfa_factor_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		a.ID, a.IdentityID, a.IdentifierHash, a.Outcome, a.FailureReason, a.IPAddress,
		a.UserAgent, a.DeviceFingerprint, a.AttemptedAt, a.SessionID, a.MFAFactorType,
	)
	if err != nil {
		return fmt.Errorf("auth repository: create login attempt: %w", err)
	}
	return nil
}
