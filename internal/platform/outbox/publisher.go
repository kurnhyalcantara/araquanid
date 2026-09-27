package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	kafkago "github.com/segmentio/kafka-go"
)

// RelayConfig configures the poll cadence and batch size of the outbox
// relay.
type RelayConfig struct {
	PollInterval time.Duration
	BatchSize    int
}

// Relay polls outbox_events for unpublished rows, publishes each to a single
// Kafka topic (message key = aggregate_id; consumers filter on the JSON
// `event_type` field), and marks it published on success. A publish failure
// leaves the row for the next poll, incrementing its attempt counter.
type Relay struct {
	pool   *pgxpool.Pool
	writer *kafkago.Writer
	cfg    RelayConfig
	log    *slog.Logger
}

// NewRelay builds a Relay. writer's Topic must already be set by the caller.
func NewRelay(pool *pgxpool.Pool, writer *kafkago.Writer, cfg RelayConfig, log *slog.Logger) *Relay {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	return &Relay{pool: pool, writer: writer, cfg: cfg, log: log}
}

// Run polls until ctx is cancelled, at which point it returns
// context.Canceled (the caller's shutdown path treats that as a clean stop,
// not a failure).
func (r *Relay) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.publishBatch(ctx); err != nil && !errors.Is(err, context.Canceled) {
				r.log.Error("outbox: publish batch failed", slog.String("error", err.Error()))
			}
		}
	}
}

type outboxRow struct {
	id            string
	aggregateType string
	aggregateID   string
	eventType     string
	payload       []byte
}

func (r *Relay) publishBatch(ctx context.Context) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("outbox: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id, aggregate_type, aggregate_id, event_type, payload
		FROM outbox_events
		WHERE published_at IS NULL
		ORDER BY created_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, r.cfg.BatchSize)
	if err != nil {
		return fmt.Errorf("outbox: select unpublished: %w", err)
	}

	var batch []outboxRow
	for rows.Next() {
		var row outboxRow
		if err := rows.Scan(&row.id, &row.aggregateType, &row.aggregateID, &row.eventType, &row.payload); err != nil {
			rows.Close()
			return fmt.Errorf("outbox: scan: %w", err)
		}
		batch = append(batch, row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("outbox: rows: %w", err)
	}
	if len(batch) == 0 {
		return nil
	}

	messages := make([]kafkago.Message, 0, len(batch))
	for _, row := range batch {
		messages = append(messages, kafkago.Message{
			Key:   []byte(row.aggregateID),
			Value: row.payload,
		})
	}
	if err := r.writer.WriteMessages(ctx, messages...); err != nil {
		return r.markFailed(ctx, tx, batch, err)
	}

	ids := make([]string, len(batch))
	for i, row := range batch {
		ids[i] = row.id
	}
	if _, err := tx.Exec(ctx, `UPDATE outbox_events SET published_at = now() WHERE id = ANY($1)`, ids); err != nil {
		return fmt.Errorf("outbox: mark published: %w", err)
	}
	return tx.Commit(ctx)
}

func (r *Relay) markFailed(ctx context.Context, tx pgx.Tx, batch []outboxRow, publishErr error) error {
	ids := make([]string, len(batch))
	for i, row := range batch {
		ids[i] = row.id
	}
	_, err := tx.Exec(ctx, `
		UPDATE outbox_events
		SET attempts = attempts + 1, last_error = $2
		WHERE id = ANY($1)`, ids, publishErr.Error())
	if err != nil {
		return fmt.Errorf("outbox: record publish failure (publish err: %v): %w", publishErr, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("outbox: commit failure record: %w", err)
	}
	return fmt.Errorf("outbox: publish batch: %w", publishErr)
}
