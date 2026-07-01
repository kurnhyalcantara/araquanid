// Package repository defines the outbound port for the example feature. A
// repository is any outbound dependency abstraction — it may be backed by
// PostgreSQL, Redis, Kafka, another gRPC/HTTP service, or a third-party API;
// it is not limited to database access. Adapters live in sibling packages,
// one per backing store (db, redis, kafka, ...), and are composed by the
// container.
package repository

import (
	"context"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

// Repository is the outbound port consumed by the usecase. Implementations:
// db.NewPostgres (primary store) and redis.NewCache (read-through cache
// decorator).
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
