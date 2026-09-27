package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/platform/outbox"
)

type txOutbox struct{ tx pgx.Tx }

// Append maps each domain event to an outbox.Event (JSON-encoding the event
// itself as the payload) and inserts them in the same transaction as the
// aggregate state they describe (PRD §10.4).
func (t *txOutbox) Append(ctx context.Context, events []domain.DomainEvent) error {
	if len(events) == 0 {
		return nil
	}
	rows := make([]outbox.Event, len(events))
	for i, e := range events {
		payload, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("login/db: marshal event %s: %w", e.EventType(), err)
		}
		rows[i] = outbox.Event{
			ID:            uuid.NewString(),
			AggregateType: e.AggregateType(),
			AggregateID:   e.AggregateID(),
			EventType:     e.EventType(),
			Payload:       payload,
			OccurredAt:    e.OccurredAt(),
		}
	}
	return outbox.InsertEvents(ctx, t.tx, rows)
}
