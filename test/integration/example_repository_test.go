//go:build integration

// Integration tests run against real Postgres/Redis, e.g. the
// docker-compose services:
//
//	make docker-up && make migrate-up && make test-integration
//
// Connection settings come from the usual ARAQUANID_* environment variables.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kurnhyalcantara/kingler/pkg/platform/postgres"

	"github.com/kurnhyalcantara/araquanid/config"
	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/repository"
)

func TestPostgresExampleRepository(t *testing.T) {
	// Default to the docker-compose credentials so the test runs out of the
	// box; real environments override via ARAQUANID_* variables.
	if os.Getenv("ARAQUANID_POSTGRES__PASSWORD") == "" {
		t.Setenv("ARAQUANID_POSTGRES__PASSWORD", "araquanid")
	}

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := postgres.New(ctx, postgres.Config{
		DSN:             cfg.Postgres.DSN(),
		MaxConns:        cfg.Postgres.MaxConns,
		MinConns:        cfg.Postgres.MinConns,
		MaxConnLifetime: cfg.Postgres.MaxConnLifetime,
	})
	if err != nil {
		t.Fatalf("connect postgres (are the compose services up and migrated?): %v", err)
	}
	defer pool.Close()

	repo := repository.NewPostgres(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	e := &domain.Example{
		ID:          uuid.NewString(),
		Name:        "integration",
		Description: "created by integration test",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := repo.Create(ctx, e); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM examples WHERE id = $1`, e.ID)
	})

	got, err := repo.GetByID(ctx, e.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Name != e.Name || !got.CreatedAt.Equal(e.CreatedAt) {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", got, e)
	}

	got.Update("integration-updated", "updated description", now.Add(time.Minute))
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	updated, err := repo.GetByID(ctx, e.ID)
	if err != nil {
		t.Fatalf("GetByID after update: %v", err)
	}
	if updated.Name != "integration-updated" {
		t.Fatal("update not persisted")
	}

	list, total, err := repo.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total < 1 || len(list) < 1 {
		t.Fatalf("expected at least one example, got total=%d len=%d", total, len(list))
	}

	if err := repo.Delete(ctx, e.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, e.ID); err != domain.ErrNotFound {
		t.Fatalf("expected domain.ErrNotFound after delete, got %v", err)
	}
}
