package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

type txSessions struct{ q querier }

// Create persists a newly-created ACTIVE session. clientID is pure
// persistence bookkeeping (see repository.TxSessions.Create) backing the
// FR-LOGIN-012 concurrent-session queries below.
func (t *txSessions) Create(ctx context.Context, s *domain.AuthenticationSession, clientID string) error {
	snap := s.Snapshot()

	factorsJSON, err := marshalFactors(snap.FactorsUsed)
	if err != nil {
		return err
	}

	var deviceID *string
	if snap.DeviceID != "" {
		d := string(snap.DeviceID)
		deviceID = &d
	}

	_, err = t.q.Exec(ctx, `
		INSERT INTO authentication_sessions
			(id, identity_id, device_id, client_id, status, aal, mfa_factors_used,
			 created_at, last_activity_at, idle_timeout_secs, absolute_expires_at,
			 creation_ip, creation_user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		string(snap.ID), string(snap.IdentityID), deviceID, clientID, string(snap.Status), string(snap.AAL),
		factorsJSON, snap.CreatedAt, snap.LastActivityAt, int(snap.IdleTimeout.Seconds()), snap.AbsoluteExpiresAt,
		snap.Client.IP.String(), snap.Client.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("login/db: create session: %w", err)
	}
	return nil
}

// Revoke persists the terminal state of a session already transitioned via
// (*domain.AuthenticationSession).Revoke in memory (used by the FR-LOGIN-012
// concurrent-session eviction branches).
func (t *txSessions) Revoke(ctx context.Context, s *domain.AuthenticationSession) error {
	snap := s.Snapshot()
	var reason *string
	if snap.RevokeReason != "" {
		r := string(snap.RevokeReason)
		reason = &r
	}
	_, err := t.q.Exec(ctx, `
		UPDATE authentication_sessions
		SET status = $2, revoked_at = $3, revoke_reason = $4
		WHERE id = $1`,
		string(snap.ID), string(snap.Status), snap.RevokedAt, reason,
	)
	if err != nil {
		return fmt.Errorf("login/db: revoke session: %w", err)
	}
	return nil
}

func (t *txSessions) CountActive(ctx context.Context, identityID, clientID string) (int, error) {
	var count int
	err := t.q.QueryRow(ctx, `
		SELECT COUNT(*) FROM authentication_sessions
		WHERE identity_id = $1 AND client_id = $2 AND status = 'ACTIVE'`,
		identityID, clientID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("login/db: count active sessions: %w", err)
	}
	return count, nil
}

func (t *txSessions) FindOldestActive(ctx context.Context, identityID, clientID string) (*domain.AuthenticationSession, error) {
	row := t.q.QueryRow(ctx, sessionSelectColumns+`
		FROM authentication_sessions
		WHERE identity_id = $1 AND client_id = $2 AND status = 'ACTIVE'
		ORDER BY created_at ASC
		LIMIT 1`, identityID, clientID)

	s, err := scanSessionRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil //nolint:nilnil // "no active session" is a valid, non-error outcome
	}
	if err != nil {
		return nil, fmt.Errorf("login/db: find oldest active session: %w", err)
	}
	return s, nil
}

func (t *txSessions) ListActive(ctx context.Context, identityID, clientID string) ([]*domain.AuthenticationSession, error) {
	rows, err := t.q.Query(ctx, sessionSelectColumns+`
		FROM authentication_sessions
		WHERE identity_id = $1 AND client_id = $2 AND status = 'ACTIVE'
		ORDER BY created_at ASC`, identityID, clientID)
	if err != nil {
		return nil, fmt.Errorf("login/db: list active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*domain.AuthenticationSession
	for rows.Next() {
		s, err := scanSessionRow(rows)
		if err != nil {
			return nil, fmt.Errorf("login/db: scan active session: %w", err)
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("login/db: list active sessions rows: %w", err)
	}
	return sessions, nil
}

const sessionSelectColumns = `
	SELECT id, identity_id, device_id, status, aal, mfa_factors_used,
	       created_at, last_activity_at, idle_timeout_secs, absolute_expires_at,
	       creation_ip, creation_user_agent, revoked_at, revoke_reason`

// rowScanner is satisfied by both pgx.Row (QueryRow) and pgx.Rows (Query),
// letting scanSessionRow serve both single-row and multi-row callers.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanSessionRow(row rowScanner) (*domain.AuthenticationSession, error) {
	var (
		id, identityID, status, aal, creationIP, creationUA string
		deviceID                                            *string
		factorsJSON                                         []byte
		createdAt, lastActivityAt, absoluteExpiresAt        time.Time
		idleSecs                                            int
		revokedAt                                           *time.Time
		revokeReason                                        *string
	)
	if err := row.Scan(&id, &identityID, &deviceID, &status, &aal, &factorsJSON,
		&createdAt, &lastActivityAt, &idleSecs, &absoluteExpiresAt,
		&creationIP, &creationUA, &revokedAt, &revokeReason); err != nil {
		return nil, err
	}

	factors, err := unmarshalFactors(factorsJSON)
	if err != nil {
		return nil, err
	}

	var dRef domain.DeviceRef
	if deviceID != nil {
		dRef = domain.DeviceRef(*deviceID)
	}

	ip, err := netip.ParseAddr(creationIP)
	if err != nil {
		return nil, fmt.Errorf("parse creation_ip %q: %w", creationIP, err)
	}

	var reason domain.RevokeReason
	if revokeReason != nil {
		reason = domain.RevokeReason(*revokeReason)
	}

	snap := domain.SessionSnapshot{
		ID:                domain.SessionID(id),
		IdentityID:        domain.IdentityRef(identityID),
		DeviceID:          dRef,
		Status:            domain.SessionStatus(status),
		AAL:               domain.AAL(aal),
		FactorsUsed:       factors,
		CreatedAt:         createdAt,
		LastActivityAt:    lastActivityAt,
		IdleTimeout:       time.Duration(idleSecs) * time.Second,
		AbsoluteExpiresAt: absoluteExpiresAt,
		RevokedAt:         revokedAt,
		RevokeReason:      reason,
		Client:            domain.ClientInfo{IP: ip, UserAgent: creationUA},
	}
	return domain.RehydrateSession(snap)
}

func marshalFactors(factors []domain.FactorType) ([]byte, error) {
	raw := make([]string, len(factors))
	for i, f := range factors {
		raw[i] = string(f)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("login/db: marshal factors: %w", err)
	}
	return b, nil
}

func unmarshalFactors(b []byte) ([]domain.FactorType, error) {
	var raw []string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("login/db: unmarshal factors: %w", err)
	}
	factors := make([]domain.FactorType, len(raw))
	for i, f := range raw {
		factors[i] = domain.FactorType(f)
	}
	return factors, nil
}
