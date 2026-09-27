package db

import (
	"context"
	"fmt"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
)

// Record implements the standalone (non-transactional) path — used for the
// rate-limited and identity-not-found outcomes, which never enter a
// UnitOfWork transaction.
func (p *Postgres) Record(ctx context.Context, a repository.LoginAttemptRecord) error {
	return recordLoginAttempt(ctx, p.pool, a)
}

type loginAttempts struct{ q querier }

func (l *loginAttempts) Record(ctx context.Context, a repository.LoginAttemptRecord) error {
	return recordLoginAttempt(ctx, l.q, a)
}

func recordLoginAttempt(ctx context.Context, q querier, a repository.LoginAttemptRecord) error {
	_, err := q.Exec(ctx, `
		INSERT INTO login_attempts
			(id, identity_id, identifier_hash, outcome, failure_reason, ip_address, user_agent,
			 device_fingerprint, attempted_at, session_id, mfa_factor_type)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		a.IdentityID, a.IdentifierHash, a.Outcome, a.FailureReason, a.IPAddress, a.UserAgent,
		nullIfEmpty(a.DeviceFingerprint), a.AttemptedAt, a.SessionID, nullIfEmpty(a.MFAFactorType))
	if err != nil {
		return fmt.Errorf("login/db: record login attempt: %w", err)
	}
	return nil
}

// nullIfEmpty returns nil for an empty string so it lands as SQL NULL
// rather than an empty string in a nullable column.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
