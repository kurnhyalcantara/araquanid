package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

// FindByIdentity loads the credential row for identityID. Password history
// is deliberately not loaded here: Login never calls ChangePassword or
// ResetPassword (the only domain methods that read history), so rehydrating
// it would be wasted work on the hot path.
func (p *Postgres) FindByIdentity(ctx context.Context, identityID string) (*domain.Credential, error) {
	return findCredentialByIdentity(ctx, p.pool, identityID)
}

func findCredentialByIdentity(ctx context.Context, q querier, identityID string) (*domain.Credential, error) {
	row := q.QueryRow(ctx, `
		SELECT id, identity_id, password_hash, password_salt, password_algorithm,
		       password_version, password_created_at, password_expires_at,
		       force_password_change, failed_attempt_count, last_failed_at,
		       lockout_status, locked_at, locked_until, lockout_history_count
		FROM credentials
		WHERE identity_id = $1`, identityID)

	var (
		id, idIdentity, hash, salt, algorithm, lockoutStatus string
		version, failedCount, lockoutHistoryCount            int
		createdAt                                            time.Time
		expiresAt, lastFailedAt, lockedAt, lockedUntil       *time.Time
		forcePasswordChange                                  bool
	)
	err := row.Scan(&id, &idIdentity, &hash, &salt, &algorithm, &version, &createdAt, &expiresAt,
		&forcePasswordChange, &failedCount, &lastFailedAt, &lockoutStatus, &lockedAt, &lockedUntil, &lockoutHistoryCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrCredentialNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("login/db: find credential: %w", err)
	}

	passwordHash, err := domain.NewPasswordHash(hash, salt, domain.PasswordAlgorithm(algorithm), version)
	if err != nil {
		return nil, fmt.Errorf("login/db: rehydrate password hash: %w", err)
	}

	snap := domain.CredentialSnapshot{
		ID:                  domain.CredentialID(id),
		IdentityID:          domain.IdentityRef(idIdentity),
		Password:            passwordHash,
		PasswordCreatedAt:   createdAt,
		PasswordExpiresAt:   expiresAt,
		ForcePasswordChange: forcePasswordChange,
		FailedAttemptCount:  failedCount,
		LastFailedAt:        lastFailedAt,
		LockoutStatus:       domain.LockoutStatus(lockoutStatus),
		LockedAt:            lockedAt,
		LockedUntil:         lockedUntil,
		LockoutHistoryCount: lockoutHistoryCount,
	}
	return domain.RehydrateCredential(snap, domain.DefaultCredentialPolicy())
}

type txCredentials struct{ q querier }

// Save persists every mutable field of an already-existing credential row
// (Login never creates a credential — that belongs to a provisioning
// feature this repository does not implement).
func (t *txCredentials) Save(ctx context.Context, c *domain.Credential) error {
	snap := c.Snapshot()
	_, err := t.q.Exec(ctx, `
		UPDATE credentials SET
			password_hash = $2,
			password_salt = $3,
			password_created_at = $4,
			password_expires_at = $5,
			force_password_change = $6,
			failed_attempt_count = $7,
			last_failed_at = $8,
			lockout_status = $9,
			locked_at = $10,
			locked_until = $11,
			lockout_history_count = $12,
			updated_at = now()
		WHERE id = $1`,
		string(snap.ID), snap.Password.Hash(), snap.Password.Salt(), snap.PasswordCreatedAt,
		snap.PasswordExpiresAt, snap.ForcePasswordChange, snap.FailedAttemptCount, snap.LastFailedAt,
		string(snap.LockoutStatus), snap.LockedAt, snap.LockedUntil, snap.LockoutHistoryCount,
	)
	if err != nil {
		return fmt.Errorf("login/db: save credential: %w", err)
	}
	return nil
}
