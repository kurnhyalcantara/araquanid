package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
)

// FindByFingerprint implements the FR-DEVICE-002 read-only lookup, excluding
// revoked devices per BR-012 (a revoked fingerprint can never re-register or
// be treated as recognized again).
func (p *Postgres) FindByFingerprint(ctx context.Context, identityID, fingerprintHash string) (*repository.RegisteredDevice, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, trust_status, last_seen_at
		FROM registered_devices
		WHERE identity_id = $1 AND fingerprint_hash = $2 AND trust_status != 'REVOKED'`,
		identityID, fingerprintHash)

	var d repository.RegisteredDevice
	err := row.Scan(&d.ID, &d.TrustStatus, &d.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil //nolint:nilnil // "not found" is a valid, non-error outcome for this port
	}
	if err != nil {
		return nil, fmt.Errorf("login/db: find device: %w", err)
	}
	return &d, nil
}

type txDevices struct{ q querier }

// Register inserts a new registered_devices row (FR-DEVICE-002 step "new
// device"), inferring nothing itself — displayName is computed by the
// caller (FR-DEVICE-003). Returns ("", nil), not an error, when a REVOKED
// row already occupies the unique (identity_id, fingerprint_hash) key
// (BR-012): the device stays unrecognized rather than being re-registered.
func (t *txDevices) Register(ctx context.Context, identityID, fingerprintHash string, fingerprintVersion int, displayName, registrationIP string, now time.Time) (string, error) {
	row := t.q.QueryRow(ctx, `
		INSERT INTO registered_devices
			(id, identity_id, fingerprint_hash, fingerprint_version, display_name, trust_status, registration_ip, last_seen_at, created_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, 'REGISTERED', $5, $6, $6)
		ON CONFLICT (identity_id, fingerprint_hash) DO NOTHING
		RETURNING id`,
		identityID, fingerprintHash, fingerprintVersion, displayName, registrationIP, now)

	var id string
	err := row.Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("login/db: register device: %w", err)
	}
	return id, nil
}

// Touch updates last_seen_at for a recognized device (FR-DEVICE-002 step
// "existing device").
func (t *txDevices) Touch(ctx context.Context, deviceID string, at time.Time) error {
	_, err := t.q.Exec(ctx, `UPDATE registered_devices SET last_seen_at = $2 WHERE id = $1`, deviceID, at)
	if err != nil {
		return fmt.Errorf("login/db: touch device: %w", err)
	}
	return nil
}
