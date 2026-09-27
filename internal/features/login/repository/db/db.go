// Package db is the Postgres adapter for the login feature's repository
// ports (internal/features/login/repository). Postgres implements every
// read-only port plus repository.UnitOfWork; Execute hands each write port
// a transaction-scoped implementation so a caller's writes commit
// atomically with the outbox rows recording them.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
)

// querier is satisfied by both *pgxpool.Pool (standalone reads) and pgx.Tx
// (writes inside a UnitOfWork transaction), so each adapter method's SQL is
// written once and used in both modes.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Postgres implements CredentialRepository, DeviceRepository,
// MFAFactorRepository, LoginAttemptRepository, and UnitOfWork.
type Postgres struct {
	pool *pgxpool.Pool
}

// New builds a Postgres adapter over an existing pool.
func New(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// Execute runs fn inside a single Postgres transaction, committing only if
// fn returns nil.
func (p *Postgres) Execute(ctx context.Context, fn func(ctx context.Context, r repository.TxRepositories) error) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("login/db: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	txRepos := repository.TxRepositories{
		Credentials:   &txCredentials{q: tx},
		Sessions:      &txSessions{q: tx},
		RefreshTokens: &txRefreshTokens{q: tx},
		Devices:       &txDevices{q: tx},
		LoginAttempts: &loginAttempts{q: tx},
		Outbox:        &txOutbox{tx: tx},
	}
	if err := fn(ctx, txRepos); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("login/db: commit tx: %w", err)
	}
	return nil
}
