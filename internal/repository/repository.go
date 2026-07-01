// Package repository defines the outbound port and its adapters. A repository
// is any outbound dependency abstraction — it may be backed by PostgreSQL,
// Redis, another gRPC/HTTP service, a third-party API, or a message broker; it
// is not limited to database access.
package repository

import (
	"context"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

// Repository is the outbound port consumed by the usecase. Implementations:
// NewPostgres (primary store) and NewRedisCache (read-through cache decorator).
type Repository interface {
	Create(ctx context.Context, e *domain.Example) error
	GetByID(ctx context.Context, id string) (*domain.Example, error)
	// List returns a page of examples ordered by creation time (newest first)
	// along with the total count across all pages.
	List(ctx context.Context, limit, offset int) ([]*domain.Example, int64, error)
	// Update persists mutations of an existing example.
	Update(ctx context.Context, e *domain.Example) error
	Delete(ctx context.Context, id string) error
}
