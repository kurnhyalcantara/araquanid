-- outbox_events implements the transactional outbox pattern: domain events
-- are written in the same DB transaction as the aggregate they describe, and
-- a separate relay (internal/platform/outbox) publishes them to Kafka and
-- marks them published (PRD §10.4).
CREATE TABLE outbox_events (
    id             UUID PRIMARY KEY,
    aggregate_type TEXT        NOT NULL,
    aggregate_id   TEXT        NOT NULL,
    event_type     TEXT        NOT NULL,
    payload        JSONB       NOT NULL,
    occurred_at    TIMESTAMPTZ NOT NULL,
    published_at   TIMESTAMPTZ,
    attempts       INT         NOT NULL DEFAULT 0,
    last_error     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Partial index backs the relay's claim query (unpublished rows only).
CREATE INDEX outbox_events_unpublished_idx
    ON outbox_events (created_at)
    WHERE published_at IS NULL;
CREATE INDEX outbox_events_aggregate_idx
    ON outbox_events (aggregate_type, aggregate_id);
