// Package outbox implements the transactional outbox pattern (PRD §10.4):
// domain events are inserted into the outbox_events table in the same DB
// transaction as the aggregate they describe, and a separate Relay publishes
// them to Kafka asynchronously, marking each row published on success. This
// package is shared across features; only the domain-event-to-Event mapping
// is feature-specific (kept in each feature's own repository/db package).
package outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Event is one row of outbox_events.
type Event struct {
	ID            string
	AggregateType string
	AggregateID   string
	EventType     string
	Payload       []byte // JSON
	OccurredAt    time.Time
}

// InsertEvents writes events to outbox_events inside tx, so they commit
// atomically with whatever else the caller's transaction does.
func InsertEvents(ctx context.Context, tx pgx.Tx, events []Event) error {
	for _, e := range events {
		_, err := tx.Exec(ctx, `
			INSERT INTO outbox_events (id, aggregate_type, aggregate_id, event_type, payload, occurred_at)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			e.ID, e.AggregateType, e.AggregateID, e.EventType, e.Payload, e.OccurredAt,
		)
		if err != nil {
			return fmt.Errorf("outbox: insert event %s: %w", e.EventType, err)
		}
	}
	return nil
}
