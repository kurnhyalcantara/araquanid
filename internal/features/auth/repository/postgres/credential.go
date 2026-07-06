// Package db is the PostgreSQL adapter for the auth feature's repository ports.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	domain_auth "github.com/kurnhyalcantara/araquanid/internal/domain/auth"
)

type credentialRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresCredentialRepository returns the PostgreSQL-backed credential repository.
func NewPostgresCredentialRepository(pool *pgxpool.Pool) domain_auth.CredentialRepository {
	return &credentialRepository{pool: pool}
}

const credentialColumns = `id, identity_id, password_hash, password_algorithm, password_version,
	password_created_at, password_expires_at, force_password_change, failed_attempt_count,
	last_failed_at, lockout_status, locked_at, locked_until, lockout_history_count,
	created_at, updated_at`

func (r *credentialRepository) GetByIdentityID(ctx context.Context, identityID string) (*domain_auth.Credential, error) {
	var c domain_auth.Credential
	err := r.pool.QueryRow(ctx,
		`SELECT `+credentialColumns+` FROM credentials WHERE identity_id = $1`, identityID,
	).Scan(
		&c.ID, &c.IdentityID, &c.PasswordHash, &c.PasswordAlgorithm, &c.PasswordVersion,
		&c.PasswordCreatedAt, &c.PasswordExpiresAt, &c.ForcePasswordChange, &c.FailedAttemptCount,
		&c.LastFailedAt, &c.LockoutStatus, &c.LockedAt, &c.LockedUntil, &c.LockoutHistoryCount,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain_auth.ErrCredentialNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("auth repository: get credential: %w", err)
	}
	return &c, nil
}

func (r *credentialRepository) Update(ctx context.Context, c *domain_auth.Credential) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE credentials SET
			password_hash = $2, password_algorithm = $3, password_version = $4,
			password_created_at = $5, password_expires_at = $6, force_password_change = $7,
			failed_attempt_count = $8, last_failed_at = $9, lockout_status = $10,
			locked_at = $11, locked_until = $12, lockout_history_count = $13, updated_at = now()
		WHERE id = $1`,
		c.ID, c.PasswordHash, c.PasswordAlgorithm, c.PasswordVersion,
		c.PasswordCreatedAt, c.PasswordExpiresAt, c.ForcePasswordChange,
		c.FailedAttemptCount, c.LastFailedAt, c.LockoutStatus,
		c.LockedAt, c.LockedUntil, c.LockoutHistoryCount,
	)
	if err != nil {
		return fmt.Errorf("auth repository: update credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain_auth.ErrCredentialNotFound
	}
	return nil
}
