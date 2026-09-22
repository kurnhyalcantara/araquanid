// Package domain holds the core business entities and rules. It is pure:
// stdlib and other domain packages only — no transport, infrastructure, or
// framework imports. Repository and usecase ports are declared by the
// consuming feature, not here.
package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// AuthenticationSession domain errors.
var (
	ErrSessionNotFound      = errors.New("session not found")
	ErrInvalidSession       = errors.New("invalid session")
	ErrInvalidSessionPolicy = errors.New("invalid session policy")
	ErrSessionExpired       = errors.New("session is expired")
	ErrSessionRevoked       = errors.New("session is revoked")
	ErrInvalidRevokeReason  = errors.New("invalid revoke reason")
	ErrAALFactorMismatch    = errors.New("aal does not match verified factors")
)

// SessionID is the opaque, unique identifier of an AuthenticationSession.
type SessionID string

// IdentityRef is an opaque reference to an identity owned by the Identity context.
type IdentityRef string

// DeviceRef is an optional reference to a RegisteredDevice.
type DeviceRef string

// AAL is the NIST SP 800-63B Authenticator Assurance Level.
type AAL string

const (
	AAL1 AAL = "AAL1"
	AAL2 AAL = "AAL2"
	AAL3 AAL = "AAL3"
)

// Valid reports whether a is a known assurance level.
func (a AAL) Valid() bool { return a == AAL1 || a == AAL2 || a == AAL3 }

// FactorType enumerates MFA factor types.
type FactorType string

const (
	FactorTOTP    FactorType = "TOTP"
	FactorSMSOTP  FactorType = "SMS_OTP"
	FactorFIDO2   FactorType = "FIDO2"
	FactorPasskey FactorType = "PASSKEY"
)

// SessionStatus is the lifecycle status of a session.
type SessionStatus string

const (
	SessionStatusActive  SessionStatus = "ACTIVE"
	SessionStatusExpired SessionStatus = "EXPIRED"
	SessionStatusRevoked SessionStatus = "REVOKED"
)

// Valid reports whether s is a known session status.
func (s SessionStatus) Valid() bool {
	return s == SessionStatusActive || s == SessionStatusExpired || s == SessionStatusRevoked
}

// RevokeReason explains why a session ended (PRD §13.5).
type RevokeReason string

const (
	ReasonUserLogout       RevokeReason = "USER_LOGOUT"
	ReasonAdminForceLogout RevokeReason = "ADMIN_FORCE_LOGOUT"
	ReasonPasswordChanged  RevokeReason = "PASSWORD_CHANGED"
	ReasonPasswordReset    RevokeReason = "PASSWORD_RESET"
	ReasonDeviceRevoked    RevokeReason = "DEVICE_REVOKED"
	ReasonSecurityEvent    RevokeReason = "SECURITY_EVENT"
	ReasonExpiredIdle      RevokeReason = "SESSION_EXPIRED_IDLE"
	ReasonExpiredAbsolute  RevokeReason = "SESSION_EXPIRED_ABSOLUTE"
)

// IsManual reports whether r can be passed to Revoke.
func (r RevokeReason) IsManual() bool {
	switch r {
	case ReasonUserLogout, ReasonAdminForceLogout, ReasonPasswordChanged,
		ReasonPasswordReset, ReasonDeviceRevoked, ReasonSecurityEvent:
		return true
	}
	return false
}

// IsExpiry reports whether r marks a timeout-driven end of session.
func (r RevokeReason) IsExpiry() bool {
	return r == ReasonExpiredIdle || r == ReasonExpiredAbsolute
}

// SessionPolicy holds the timeouts fixed onto a session at creation
type SessionPolicy struct {
	IdleTimeout      time.Duration
	AbsoluteLifetime time.Duration
}

// DefaultSessionPolicy returns the default timeouts: 15m idle, 8h absolute.
func DefaultSessionPolicy() SessionPolicy {
	return SessionPolicy{IdleTimeout: 15 * time.Minute, AbsoluteLifetime: 8 * time.Hour}
}

// Validate checks that both timeouts are positive and idle <= absolute.
func (p SessionPolicy) Validate() error {
	if p.IdleTimeout <= 0 || p.AbsoluteLifetime <= 0 || p.IdleTimeout > p.AbsoluteLifetime {
		return fmt.Errorf("%w: idle=%s absolute=%s", ErrInvalidSessionPolicy, p.IdleTimeout, p.AbsoluteLifetime)
	}
	return nil
}

// ClientInfo is the client context observed when the session was created.
type ClientInfo struct {
	IP        netip.Addr
	UserAgent string
}

// DomainEvent is a fact emitted by an aggregate and published via the outbox
type DomainEvent interface {
	EventType() string
	AggregateType() string
	AggregateID() string
	OccurredAt() time.Time
}

const aggregateAuthenticationSession = "AuthenticationSession"

// SessionCreated — a new verified session was established (PRD §13.4).
type SessionCreated struct {
	SessionID         SessionID
	IdentityID        IdentityRef
	DeviceID          DeviceRef
	AAL               AAL
	IPAddress         netip.Addr
	IdleTimeout       time.Duration
	AbsoluteExpiresAt time.Time
	At                time.Time
}

func (e SessionCreated) EventType() string     { return "auth.SessionCreated" }
func (e SessionCreated) AggregateType() string { return aggregateAuthenticationSession }
func (e SessionCreated) AggregateID() string   { return string(e.SessionID) }
func (e SessionCreated) OccurredAt() time.Time { return e.At }

// SessionRevoked — a session ended; all related tokens are invalid
type SessionRevoked struct {
	SessionID  SessionID
	IdentityID IdentityRef
	Reason     RevokeReason
	RevokedBy  IdentityRef // empty for system-initiated expiry
	At         time.Time
}

func (e SessionRevoked) EventType() string     { return "auth.SessionRevoked" }
func (e SessionRevoked) AggregateType() string { return aggregateAuthenticationSession }
func (e SessionRevoked) AggregateID() string   { return string(e.SessionID) }
func (e SessionRevoked) OccurredAt() time.Time { return e.At }

// AuthenticationSession is the aggregate root representing an active,
// verified authentication state for a principal (PRD §7.1, FR-SESSION-*).
//
// Invariants:
//   - a session is never both ACTIVE and expired;
//   - a REVOKED or EXPIRED session can never become ACTIVE again;
//   - idle timeout and absolute expiry are immutable after creation;
//   - the AAL matches the MFA factors actually verified.
type AuthenticationSession struct {
	id                SessionID
	identity          IdentityRef
	device            DeviceRef
	aal               AAL
	factorsUsed       []FactorType
	status            SessionStatus
	createdAt         time.Time
	lastActivityAt    time.Time
	idleTimeout       time.Duration
	absoluteExpiresAt time.Time
	revokedAt         *time.Time
	revokeReason      RevokeReason
	client            ClientInfo

	events []DomainEvent
}

// NewSessionParams is the input to NewAuthenticationSession.
type NewSessionParams struct {
	ID          SessionID
	Identity    IdentityRef
	Device      DeviceRef
	AAL         AAL
	FactorsUsed []FactorType
	Client      ClientInfo
	Policy      SessionPolicy
	Now         time.Time
}

// NewAuthenticationSession creates an ACTIVE session after successful
// authentication and records SessionCreated.
func NewAuthenticationSession(p NewSessionParams) (*AuthenticationSession, error) {
	switch {
	case p.ID == "":
		return nil, fmt.Errorf("%w: id is required", ErrInvalidSession)
	case p.Identity == "":
		return nil, fmt.Errorf("%w: identity is required", ErrInvalidSession)
	case !p.AAL.Valid():
		return nil, fmt.Errorf("%w: unknown aal %q", ErrInvalidSession, p.AAL)
	case !p.Client.IP.IsValid():
		return nil, fmt.Errorf("%w: client ip is required", ErrInvalidSession)
	case p.Now.IsZero():
		return nil, fmt.Errorf("%w: creation time is required", ErrInvalidSession)
	}
	if err := p.Policy.Validate(); err != nil {
		return nil, err
	}
	if err := validateAALFactors(p.AAL, p.FactorsUsed); err != nil {
		return nil, err
	}

	now := p.Now.UTC()
	s := &AuthenticationSession{
		id:                p.ID,
		identity:          p.Identity,
		device:            p.Device,
		aal:               p.AAL,
		factorsUsed:       slices.Clone(p.FactorsUsed),
		status:            SessionStatusActive,
		createdAt:         now,
		lastActivityAt:    now,
		idleTimeout:       p.Policy.IdleTimeout,
		absoluteExpiresAt: now.Add(p.Policy.AbsoluteLifetime),
		client:            p.Client,
	}
	s.record(SessionCreated{
		SessionID:         s.id,
		IdentityID:        s.identity,
		DeviceID:          s.device,
		AAL:               s.aal,
		IPAddress:         s.client.IP,
		IdleTimeout:       s.idleTimeout,
		AbsoluteExpiresAt: s.absoluteExpiresAt,
		At:                now,
	})
	return s, nil
}

// validateAALFactors enforces that the assurance level matches the factors
// actually verified (PRD §4 AAL definitions).
func validateAALFactors(aal AAL, factors []FactorType) error {
	switch aal {
	case AAL1:
		if len(factors) > 0 {
			return fmt.Errorf("%w: AAL1 must not carry MFA factors", ErrAALFactorMismatch)
		}
	case AAL2:
		if len(factors) == 0 {
			return fmt.Errorf("%w: AAL2 requires at least one MFA factor", ErrAALFactorMismatch)
		}
	case AAL3:
		if !slices.Contains(factors, FactorFIDO2) {
			return fmt.Errorf("%w: AAL3 requires a FIDO2 factor", ErrAALFactorMismatch)
		}
	}
	return nil
}

// Getters — the aggregate exposes no setters.
func (s *AuthenticationSession) ID() SessionID                { return s.id }
func (s *AuthenticationSession) Identity() IdentityRef        { return s.identity }
func (s *AuthenticationSession) Device() DeviceRef            { return s.device }
func (s *AuthenticationSession) AAL() AAL                     { return s.aal }
func (s *AuthenticationSession) FactorsUsed() []FactorType    { return slices.Clone(s.factorsUsed) }
func (s *AuthenticationSession) Status() SessionStatus        { return s.status }
func (s *AuthenticationSession) CreatedAt() time.Time         { return s.createdAt }
func (s *AuthenticationSession) LastActivityAt() time.Time    { return s.lastActivityAt }
func (s *AuthenticationSession) IdleTimeout() time.Duration   { return s.idleTimeout }
func (s *AuthenticationSession) AbsoluteExpiresAt() time.Time { return s.absoluteExpiresAt }
func (s *AuthenticationSession) RevokeReason() RevokeReason   { return s.revokeReason }
func (s *AuthenticationSession) Client() ClientInfo           { return s.client }

// RevokedAt returns when the session ended, or nil while it is ACTIVE.
func (s *AuthenticationSession) RevokedAt() *time.Time {
	if s.revokedAt == nil {
		return nil
	}
	t := *s.revokedAt
	return &t
}

// IdleExpiresAt is the moment the session expires if no further activity occurs.
func (s *AuthenticationSession) IdleExpiresAt() time.Time {
	return s.lastActivityAt.Add(s.idleTimeout)
}

// IsActive reports whether the session is usable at now. A session persisted
// as ACTIVE but past either timeout is not active.
func (s *AuthenticationSession) IsActive(now time.Time) bool {
	if s.status != SessionStatusActive {
		return false
	}
	_, _, expired := s.expiryAt(now)
	return !expired
}

// EnforceExpiry transitions an ACTIVE session to EXPIRED when either timeout
// has elapsed. It reports whether a transition happened.
func (s *AuthenticationSession) EnforceExpiry(now time.Time) bool {
	if s.status != SessionStatusActive {
		return false
	}
	reason, at, expired := s.expiryAt(now)
	if !expired {
		return false
	}
	s.terminate(SessionStatusExpired, reason, "", at)
	return true
}

// Touch records activity and resets the idle timer. If the session has just expired,
// the EXPIRED transition is applied and ErrSessionExpired is returned — the caller must still persist the session.
func (s *AuthenticationSession) Touch(now time.Time) error {
	if err := s.ensureActive(now); err != nil {
		return err
	}
	now = now.UTC()
	if now.After(s.lastActivityAt) { // never move the idle timer backwards
		s.lastActivityAt = now
	}
	return nil
}

// Revoke ends the session deliberately and records SessionStatusRevoked.
func (s *AuthenticationSession) Revoke(reason RevokeReason, by IdentityRef, now time.Time) error {
	if !reason.IsManual() {
		return fmt.Errorf("%w: %q", ErrInvalidRevokeReason, reason)
	}
	if err := s.ensureActive(now); err != nil {
		return err
	}
	s.terminate(SessionStatusRevoked, reason, by, now.UTC())
	return nil
}

// PullEvents returns and clears the recorded domain events. They are meant to
// be written to the outbox in the same transaction as the state (PRD §10.4).
func (s *AuthenticationSession) PullEvents() []DomainEvent {
	ev := s.events
	s.events = nil
	return ev
}

func (s *AuthenticationSession) ensureActive(now time.Time) error {
	switch s.status {
	case SessionStatusRevoked:
		return ErrSessionRevoked
	case SessionStatusExpired:
		return ErrSessionExpired
	}
	if s.EnforceExpiry(now) {
		return ErrSessionExpired
	}
	return nil
}

// expiryAt evaluates both timeouts independently; absolute wins when both
// have elapsed. at is the exact expiry instant, not the detection time, so the
// outcome is the same whether detected lazily or by the sweeper.
func (s *AuthenticationSession) expiryAt(now time.Time) (RevokeReason, time.Time, bool) {
	if !now.Before(s.absoluteExpiresAt) {
		return ReasonExpiredAbsolute, s.absoluteExpiresAt, true
	}
	if idle := s.IdleExpiresAt(); !now.Before(idle) {
		return ReasonExpiredIdle, idle, true
	}
	return "", time.Time{}, false
}

func (s *AuthenticationSession) terminate(status SessionStatus, reason RevokeReason, by IdentityRef, at time.Time) {
	s.status = status
	s.revokedAt = &at
	s.revokeReason = reason
	s.record(SessionRevoked{
		SessionID:  s.id,
		IdentityID: s.identity,
		Reason:     reason,
		RevokedBy:  by,
		At:         at,
	})
}

func (s *AuthenticationSession) record(e DomainEvent) { s.events = append(s.events, e) }

// SessionSnapshot is the flat persistence shape of a session
// (authentication_sessions table, PRD §12). Feature repositories map to and
// from it so they never touch the aggregate's private state.
type SessionSnapshot struct {
	ID                SessionID
	IdentityID        IdentityRef
	DeviceID          DeviceRef
	Status            SessionStatus
	AAL               AAL
	FactorsUsed       []FactorType
	CreatedAt         time.Time
	LastActivityAt    time.Time
	IdleTimeout       time.Duration
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RevokeReason      RevokeReason
	Client            ClientInfo
}

// Snapshot returns a copy of the session's state for persistence.
func (s *AuthenticationSession) Snapshot() SessionSnapshot {
	return SessionSnapshot{
		ID:                s.id,
		IdentityID:        s.identity,
		DeviceID:          s.device,
		Status:            s.status,
		AAL:               s.aal,
		FactorsUsed:       slices.Clone(s.factorsUsed),
		CreatedAt:         s.createdAt,
		LastActivityAt:    s.lastActivityAt,
		IdleTimeout:       s.idleTimeout,
		AbsoluteExpiresAt: s.absoluteExpiresAt,
		RevokedAt:         s.RevokedAt(),
		RevokeReason:      s.revokeReason,
		Client:            s.client,
	}
}

// RehydrateSession rebuilds a session from storage without recording events.
// It rejects snapshots that violate the aggregate's invariants.
func RehydrateSession(snap SessionSnapshot) (*AuthenticationSession, error) {
	switch {
	case snap.ID == "" || snap.IdentityID == "":
		return nil, fmt.Errorf("%w: id and identity are required", ErrInvalidSession)
	case !snap.Status.Valid():
		return nil, fmt.Errorf("%w: unknown status %q", ErrInvalidSession, snap.Status)
	case !snap.AAL.Valid():
		return nil, fmt.Errorf("%w: unknown aal %q", ErrInvalidSession, snap.AAL)
	case snap.IdleTimeout <= 0 || !snap.AbsoluteExpiresAt.After(snap.CreatedAt):
		return nil, fmt.Errorf("%w: invalid timeouts", ErrInvalidSession)
	case snap.LastActivityAt.Before(snap.CreatedAt):
		return nil, fmt.Errorf("%w: last activity before creation", ErrInvalidSession)
	}

	switch snap.Status {
	case SessionStatusActive:
		if snap.RevokedAt != nil || snap.RevokeReason != "" {
			return nil, fmt.Errorf("%w: active session carries revocation", ErrInvalidSession)
		}
	case SessionStatusRevoked:
		if snap.RevokedAt == nil || !snap.RevokeReason.IsManual() {
			return nil, fmt.Errorf("%w: revoked session needs revoked_at and a manual reason", ErrInvalidSession)
		}
	case SessionStatusExpired:
		if snap.RevokedAt == nil || !snap.RevokeReason.IsExpiry() {
			return nil, fmt.Errorf("%w: expired session needs revoked_at and an expiry reason", ErrInvalidSession)
		}
	}

	if err := validateAALFactors(snap.AAL, snap.FactorsUsed); err != nil {
		return nil, err
	}

	s := &AuthenticationSession{
		id:                snap.ID,
		identity:          snap.IdentityID,
		device:            snap.DeviceID,
		aal:               snap.AAL,
		factorsUsed:       slices.Clone(snap.FactorsUsed),
		status:            snap.Status,
		createdAt:         snap.CreatedAt.UTC(),
		lastActivityAt:    snap.LastActivityAt.UTC(),
		idleTimeout:       snap.IdleTimeout,
		absoluteExpiresAt: snap.AbsoluteExpiresAt.UTC(),
		revokeReason:      snap.RevokeReason,
		client:            snap.Client,
	}
	if snap.RevokedAt != nil {
		t := snap.RevokedAt.UTC()
		s.revokedAt = &t
	}
	return s, nil
}
