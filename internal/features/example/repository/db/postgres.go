// Package db is the PostgreSQL adapter for the example feature's repository
// port.
package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/example/repository"
)

type postgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgres returns the PostgreSQL-backed example repository.
func NewPostgres(pool *pgxpool.Pool) repository.Repository {
	return &postgresRepository{pool: pool}
}

const exampleColumns = `id, name, description, created_at, updated_at`

func (r *postgresRepository) Create(ctx context.Context, e *domain.Example) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO examples (`+exampleColumns+`)
		VALUES ($1, $2, $3, $4, $5)`,
		e.ID, e.Name, e.Description, e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("example repository: create: %w", err)
	}
	return nil
}

func (r *postgresRepository) GetByID(ctx context.Context, id string) (*domain.Example, error) {
	var e domain.Example
	err := r.pool.QueryRow(ctx,
		`SELECT `+exampleColumns+` FROM examples WHERE id = $1`, id,
	).Scan(&e.ID, &e.Name, &e.Description, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("example repository: get: %w", err)
	}
	return &e, nil
}

func (r *postgresRepository) List(ctx context.Context, limit, offset int) ([]*domain.Example, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM examples`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("example repository: count: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT `+exampleColumns+`
		FROM examples
		ORDER BY created_at DESC, id DESC
		LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("example repository: list: %w", err)
	}
	defer rows.Close()

	examples := make([]*domain.Example, 0, limit)
	for rows.Next() {
		var e domain.Example
		if err := rows.Scan(&e.ID, &e.Name, &e.Description, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("example repository: list scan: %w", err)
		}
		examples = append(examples, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("example repository: list rows: %w", err)
	}
	return examples, total, nil
}

func (r *postgresRepository) Update(ctx context.Context, e *domain.Example) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE examples
		SET name = $2, description = $3, updated_at = $4
		WHERE id = $1`,
		e.ID, e.Name, e.Description, e.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("example repository: update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *postgresRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM examples WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("example repository: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
