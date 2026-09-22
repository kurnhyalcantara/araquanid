package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Credential domain errors.
var (
	ErrCredentialNotFound      = errors.New("credential not found")
	ErrInvalidCredential       = errors.New("invalid credential")
	ErrInvalidPasswordHash     = errors.New("invalid password hash")
	ErrInvalidLockoutPolicy    = errors.New("invalid lockout policy")
	ErrInvalidCredentialPolicy = errors.New("invalid credential policy")
	ErrAccountLocked           = errors.New("account is locked")
	ErrAccountNotLocked        = errors.New("account is not locked")
	ErrPasswordReused          = errors.New("password was used recently")
)

// CredentialID is the opaque, unique identifier of a Credential.
type CredentialID string

// PasswordAlgorithm identifies the hashing algorithm of a stored password.
type PasswordAlgorithm string

const (
	PasswordArgon2id PasswordAlgorithm = "argon2id"
	PasswordBcrypt   PasswordAlgorithm = "bcrypt" // legacy, migration only
)

// Valid reports whether a is a supported algorithm.
func (a PasswordAlgorithm) Valid() bool { return a == PasswordArgon2id || a == PasswordBcrypt }

// PasswordHash is an immutable, already-hashed password (PRD §7.3). Hashing
// and comparison happen outside the domain.
type PasswordHash struct {
	hash      string
	salt      string
	algorithm PasswordAlgorithm
	version   int
}

// NewPasswordHash builds a PasswordHash from its stored parts.
func NewPasswordHash(hash, salt string, alg PasswordAlgorithm, version int) (PasswordHash, error) {
	switch {
	case hash == "":
		return PasswordHash{}, fmt.Errorf("%w: hash is required", ErrInvalidPasswordHash)
	case salt == "":
		return PasswordHash{}, fmt.Errorf("%w: salt is required", ErrInvalidPasswordHash)
	case !alg.Valid():
		return PasswordHash{}, fmt.Errorf("%w: unknown algorithm %q", ErrInvalidPasswordHash, alg)
	case version < 1:
		return PasswordHash{}, fmt.Errorf("%w: version must be >= 1", ErrInvalidPasswordHash)
	}
	return PasswordHash{hash: hash, salt: salt, algorithm: alg, version: version}, nil
}

func (h PasswordHash) Hash() string                 { return h.hash }
func (h PasswordHash) Salt() string                 { return h.salt }
func (h PasswordHash) Algorithm() PasswordAlgorithm { return h.algorithm }
func (h PasswordHash) Version() int                 { return h.version }

// IsZero reports whether h is the zero value.
func (h PasswordHash) IsZero() bool { return h == PasswordHash{} }

// PasswordMatcher reports whether a candidate plaintext (captured by the
// caller) matches a stored hash. It lets the aggregate enforce history rules
// without knowing the hashing algorithm.
type PasswordMatcher func(stored PasswordHash) bool

// PasswordHistoryEntry is a previously used password (PRD §7.2).
type PasswordHistoryEntry struct {
	Hash      PasswordHash
	CreatedAt time.Time
}

// LockoutStatus is the lockout state of a credential (FR-LOGIN-004).
type LockoutStatus string

const (
	LockoutUnlocked  LockoutStatus = "UNLOCKED"
	LockoutTemporary LockoutStatus = "LOCKED_TEMPORARY"
	LockoutPermanent LockoutStatus = "LOCKED_PERMANENT"
)

// Valid reports whether s is a known lockout status.
func (s LockoutStatus) Valid() bool {
	return s == LockoutUnlocked || s == LockoutTemporary || s == LockoutPermanent
}

// LoginFailureReason is the failure reason carried by LoginFailed events
// raised by the credential (PRD §13.2).
type LoginFailureReason string

const (
	FailureInvalidCredentials LoginFailureReason = "INVALID_CREDENTIALS"
	FailureAccountLocked      LoginFailureReason = "ACCOUNT_LOCKED"
)

// PasswordChangeType classifies a password change (PRD §13.6).
type PasswordChangeType string

const (
	ChangeUserInitiated PasswordChangeType = "USER_INITIATED"
	ChangeForced        PasswordChangeType = "FORCED"
)

// LockoutPolicy governs failed-attempt lockout and its escalation
// (FR-LOGIN-003/004). A lock beyond len(TemporaryDurations) is permanent.
type LockoutPolicy struct {
	Threshold          int
	Window             time.Duration
	TemporaryDurations []time.Duration
}

// DefaultLockoutPolicy returns the PRD defaults: 5 failures within 15m;
// escalation 30m, 2h, then permanent.
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{
		Threshold:          5,
		Window:             15 * time.Minute,
		TemporaryDurations: []time.Duration{30 * time.Minute, 2 * time.Hour},
	}
}

// Validate checks the policy is usable.
func (p LockoutPolicy) Validate() error {
	if p.Threshold < 1 || p.Window <= 0 {
		return fmt.Errorf("%w: threshold=%d window=%s", ErrInvalidLockoutPolicy, p.Threshold, p.Window)
	}
	for _, d := range p.TemporaryDurations {
		if d <= 0 {
			return fmt.Errorf("%w: temporary duration %s", ErrInvalidLockoutPolicy, d)
		}
	}
	return nil
}

// CredentialPolicy governs password history and expiry (FR-PWD-002/003).
// MaxAge 0 means passwords never expire.
type CredentialPolicy struct {
	HistoryDepth int
	MaxAge       time.Duration
}

// DefaultCredentialPolicy returns the PRD defaults: 12 remembered passwords,
// 180-day expiry (corporate users).
func DefaultCredentialPolicy() CredentialPolicy {
	return CredentialPolicy{HistoryDepth: 12, MaxAge: 180 * 24 * time.Hour}
}

// Validate checks the policy is usable.
func (p CredentialPolicy) Validate() error {
	if p.HistoryDepth < 0 || p.MaxAge < 0 {
		return fmt.Errorf("%w: history=%d maxAge=%s", ErrInvalidCredentialPolicy, p.HistoryDepth, p.MaxAge)
	}
	return nil
}

func (p CredentialPolicy) expiryFrom(t time.Time) *time.Time {
	if p.MaxAge == 0 {
		return nil
	}
	exp := t.Add(p.MaxAge)
	return &exp
}

// AttemptContext is the client context of a login attempt (FR-LOGIN-005).
type AttemptContext struct {
	CompanyCode       string
	IP                netip.Addr
	UserAgent         string
	DeviceFingerprint string
}

const aggregateCredential = "CredentialAggregate"

// LoginFailed — a login attempt against this credential failed (PRD §13.2).
type LoginFailed struct {
	CredentialID       CredentialID
	IdentityID         IdentityRef
	CompanyCode        string
	Reason             LoginFailureReason
	FailedAttemptCount int
	IPAddress          netip.Addr
	UserAgent          string
	DeviceFingerprint  string
	At                 time.Time
}

func (e LoginFailed) EventType() string     { return "auth.LoginFailed" }
func (e LoginFailed) AggregateType() string { return aggregateCredential }
func (e LoginFailed) AggregateID() string   { return string(e.CredentialID) }
func (e LoginFailed) OccurredAt() time.Time { return e.At }

// AccountLocked — the credential was locked by policy (PRD §13.3).
// LockoutType carries the domain status; the outbox serializer maps it to the
// public contract (LOCKED_TEMPORARY -> TEMPORARY, LOCKED_PERMANENT -> PERMANENT).
type AccountLocked struct {
	CredentialID       CredentialID
	IdentityID         IdentityRef
	LockoutType        LockoutStatus
	LockedUntil        *time.Time // nil for permanent
	TriggerIP          netip.Addr
	FailedAttemptCount int
	At                 time.Time
}

func (e AccountLocked) EventType() string     { return "auth.AccountLocked" }
func (e AccountLocked) AggregateType() string { return aggregateCredential }
func (e AccountLocked) AggregateID() string   { return string(e.CredentialID) }
func (e AccountLocked) OccurredAt() time.Time { return e.At }

// AccountUnlocked — the lock was lifted, automatically or by an admin
// (US-003, PRD §13.15).
type AccountUnlocked struct {
	CredentialID        CredentialID
	IdentityID          IdentityRef
	UnlockedBy          IdentityRef   // empty for automatic unlock
	PreviousLockoutType LockoutStatus // mapped like AccountLocked.LockoutType
	At                  time.Time
}

func (e AccountUnlocked) EventType() string     { return "auth.AccountUnlocked" }
func (e AccountUnlocked) AggregateType() string { return aggregateCredential }
func (e AccountUnlocked) AggregateID() string   { return string(e.CredentialID) }
func (e AccountUnlocked) OccurredAt() time.Time { return e.At }

// PasswordChanged — the password was changed by an authenticated user
// (PRD §13.6). sessions_revoked_count is added by the usecase.
type PasswordChanged struct {
	CredentialID CredentialID
	IdentityID   IdentityRef
	ChangedBy    IdentityRef
	ChangeType   PasswordChangeType
	At           time.Time
}

func (e PasswordChanged) EventType() string     { return "auth.PasswordChanged" }
func (e PasswordChanged) AggregateType() string { return aggregateCredential }
func (e PasswordChanged) AggregateID() string   { return string(e.CredentialID) }
func (e PasswordChanged) OccurredAt() time.Time { return e.At }

// PasswordResetCompleted — the password was reset via a reset token
// (PRD §13.8).
type PasswordResetCompleted struct {
	CredentialID CredentialID
	IdentityID   IdentityRef
	At           time.Time
}

func (e PasswordResetCompleted) EventType() string     { return "auth.PasswordResetCompleted" }
func (e PasswordResetCompleted) AggregateType() string { return aggregateCredential }
func (e PasswordResetCompleted) AggregateID() string   { return string(e.CredentialID) }
func (e PasswordResetCompleted) OccurredAt() time.Time { return e.At }

// AdminInitiatedPasswordReset — an admin required a password change at next
// login (FR-PWD-007, US-007, PRD §13.16).
type AdminInitiatedPasswordReset struct {
	CredentialID CredentialID
	IdentityID   IdentityRef
	InitiatedBy  IdentityRef
	At           time.Time
}

func (e AdminInitiatedPasswordReset) EventType() string     { return "auth.AdminInitiatedPasswordReset" }
func (e AdminInitiatedPasswordReset) AggregateType() string { return aggregateCredential }
func (e AdminInitiatedPasswordReset) AggregateID() string   { return string(e.CredentialID) }
func (e AdminInitiatedPasswordReset) OccurredAt() time.Time { return e.At }

// Credential is the aggregate root holding an identity's password and lockout
// state (PRD §7.1 CredentialAggregate).
//
// Invariants:
//   - the failed-attempt count is always consistent with the lockout status;
//   - password history depth never exceeds the policy maximum;
//   - a locked credential cannot be verified.
type Credential struct {
	id                  CredentialID
	identity            IdentityRef
	password            PasswordHash
	passwordCreatedAt   time.Time
	passwordExpiresAt   *time.Time
	forcePasswordChange bool
	failedAttemptCount  int
	lastFailedAt        *time.Time
	lockoutStatus       LockoutStatus
	lockedAt            *time.Time
	lockedUntil         *time.Time
	// lockoutHistoryCount is a lifetime counter driving lockout escalation
	// (FR-LOGIN-004); it is never reset by unlocking.
	lockoutHistoryCount int
	history             []PasswordHistoryEntry // newest first

	events []DomainEvent
}

// NewCredentialParams is the input to NewCredential.
type NewCredentialParams struct {
	ID          CredentialID
	Identity    IdentityRef
	Password    PasswordHash
	Policy      CredentialPolicy
	ForceChange bool
	Now         time.Time
}

// NewCredential creates an unlocked credential. It records no event.
func NewCredential(p NewCredentialParams) (*Credential, error) {
	switch {
	case p.ID == "":
		return nil, fmt.Errorf("%w: id is required", ErrInvalidCredential)
	case p.Identity == "":
		return nil, fmt.Errorf("%w: identity is required", ErrInvalidCredential)
	case p.Password.IsZero():
		return nil, fmt.Errorf("%w: password is required", ErrInvalidCredential)
	case p.Now.IsZero():
		return nil, fmt.Errorf("%w: creation time is required", ErrInvalidCredential)
	}
	if err := p.Policy.Validate(); err != nil {
		return nil, err
	}
	now := p.Now.UTC()
	return &Credential{
		id:                  p.ID,
		identity:            p.Identity,
		password:            p.Password,
		passwordCreatedAt:   now,
		passwordExpiresAt:   p.Policy.expiryFrom(now),
		forcePasswordChange: p.ForceChange,
		lockoutStatus:       LockoutUnlocked,
	}, nil
}

// Getters — the aggregate exposes no setters.
func (c *Credential) ID() CredentialID              { return c.id }
func (c *Credential) Identity() IdentityRef         { return c.identity }
func (c *Credential) Password() PasswordHash        { return c.password }
func (c *Credential) PasswordCreatedAt() time.Time  { return c.passwordCreatedAt }
func (c *Credential) PasswordExpiresAt() *time.Time { return copyTime(c.passwordExpiresAt) }
func (c *Credential) ForcePasswordChange() bool     { return c.forcePasswordChange }
func (c *Credential) FailedAttemptCount() int       { return c.failedAttemptCount }
func (c *Credential) LastFailedAt() *time.Time      { return copyTime(c.lastFailedAt) }
func (c *Credential) LockoutStatus() LockoutStatus  { return c.lockoutStatus }
func (c *Credential) LockedAt() *time.Time          { return copyTime(c.lockedAt) }
func (c *Credential) LockedUntil() *time.Time       { return copyTime(c.lockedUntil) }
func (c *Credential) LockoutHistoryCount() int      { return c.lockoutHistoryCount }

// PasswordHistory returns previous passwords, newest first.
func (c *Credential) PasswordHistory() []PasswordHistoryEntry { return slices.Clone(c.history) }

// IsLocked reports whether the credential is locked at now. It never mutates
// state; an elapsed temporary lock is lifted by EnsureVerifiable.
func (c *Credential) IsLocked(now time.Time) bool {
	switch c.lockoutStatus {
	case LockoutPermanent:
		return true
	case LockoutTemporary:
		return now.Before(*c.lockedUntil)
	}
	return false
}

// IsPasswordExpired reports whether the password has reached its expiry.
func (c *Credential) IsPasswordExpired(now time.Time) bool {
	return c.passwordExpiresAt != nil && !now.Before(*c.passwordExpiresAt)
}

// RequiresPasswordChange reports whether the user must change the password
// before accessing protected resources (FR-PWD-003, FR-PWD-007).
func (c *Credential) RequiresPasswordChange(now time.Time) bool {
	return c.forcePasswordChange || c.IsPasswordExpired(now)
}

// EnsureVerifiable returns ErrAccountLocked while the credential is locked.
// An elapsed temporary lock is lifted here (US-003), resetting the counter and
// recording AccountUnlocked.
func (c *Credential) EnsureVerifiable(now time.Time) error {
	switch c.lockoutStatus {
	case LockoutUnlocked:
		return nil
	case LockoutPermanent:
		return ErrAccountLocked
	}
	if now.Before(*c.lockedUntil) {
		return ErrAccountLocked
	}
	c.unlock("", *c.lockedUntil)
	return nil
}

// RecordFailedAttempt registers a failed verification (FR-LOGIN-003). It
// records LoginFailed and, when the threshold is reached, locks the credential
// and records AccountLocked. On an already locked credential it records
// LoginFailed(ACCOUNT_LOCKED), leaves the counter untouched and returns
// ErrAccountLocked.
func (c *Credential) RecordFailedAttempt(attempt AttemptContext, policy LockoutPolicy, now time.Time) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	now = now.UTC()
	if err := c.EnsureVerifiable(now); err != nil {
		c.recordLoginFailed(attempt, FailureAccountLocked, now)
		return err
	}

	// Failures separated by more than the window are not consecutive.
	if c.lastFailedAt != nil && now.Sub(*c.lastFailedAt) > policy.Window {
		c.failedAttemptCount = 0
	}
	c.failedAttemptCount++
	c.lastFailedAt = &now
	c.recordLoginFailed(attempt, FailureInvalidCredentials, now)

	if c.failedAttemptCount >= policy.Threshold {
		c.lock(policy, attempt.IP, now)
	}
	return nil
}

// RecordSuccessfulVerification resets the consecutive-failure counter.
func (c *Credential) RecordSuccessfulVerification(now time.Time) error {
	if err := c.EnsureVerifiable(now); err != nil {
		return err
	}
	c.failedAttemptCount = 0
	c.lastFailedAt = nil
	return nil
}

// Unlock lifts a temporary or permanent lock on behalf of an administrator
// (UnlockAccount command).
func (c *Credential) Unlock(by IdentityRef, now time.Time) error {
	if c.lockoutStatus == LockoutUnlocked {
		return ErrAccountNotLocked
	}
	c.unlock(by, now.UTC())
	return nil
}

// ChangePassword replaces the password for an authenticated user
// (FR-PWD-006). The caller verifies the current password beforehand; isReuse
// must match the new plaintext against stored hashes.
func (c *Credential) ChangePassword(newHash PasswordHash, isReuse PasswordMatcher, by IdentityRef, policy CredentialPolicy, now time.Time) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	now = now.UTC()
	if err := c.EnsureVerifiable(now); err != nil {
		return err
	}
	changeType := ChangeUserInitiated
	if c.RequiresPasswordChange(now) {
		changeType = ChangeForced
	}
	if err := c.replacePassword(newHash, isReuse, policy, now); err != nil {
		return err
	}
	c.record(PasswordChanged{
		CredentialID: c.id,
		IdentityID:   c.identity,
		ChangedBy:    by,
		ChangeType:   changeType,
		At:           now,
	})
	return nil
}

// ResetPassword replaces the password via a validated reset token
// (FR-PWD-005). It is refused on a permanently locked credential; a temporary
// lock is left in place.
func (c *Credential) ResetPassword(newHash PasswordHash, isReuse PasswordMatcher, policy CredentialPolicy, now time.Time) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if c.lockoutStatus == LockoutPermanent {
		return ErrAccountLocked
	}
	now = now.UTC()
	if err := c.replacePassword(newHash, isReuse, policy, now); err != nil {
		return err
	}
	c.record(PasswordResetCompleted{CredentialID: c.id, IdentityID: c.identity, At: now})
	return nil
}

// MarkForcePasswordChange requires a password change at next login
// (FR-PWD-007). It is idempotent: only the first call records an event.
func (c *Credential) MarkForcePasswordChange(by IdentityRef, now time.Time) error {
	if by == "" {
		return fmt.Errorf("%w: initiator is required", ErrInvalidCredential)
	}
	if c.forcePasswordChange {
		return nil
	}
	c.forcePasswordChange = true
	c.record(AdminInitiatedPasswordReset{CredentialID: c.id, IdentityID: c.identity, InitiatedBy: by, At: now.UTC()})
	return nil
}

// PullEvents returns and clears the recorded domain events.
func (c *Credential) PullEvents() []DomainEvent {
	ev := c.events
	c.events = nil
	return ev
}

func (c *Credential) replacePassword(newHash PasswordHash, isReuse PasswordMatcher, policy CredentialPolicy, now time.Time) error {
	if newHash.IsZero() {
		return fmt.Errorf("%w: new password is required", ErrInvalidPasswordHash)
	}
	if isReuse == nil {
		return fmt.Errorf("%w: reuse matcher is required", ErrInvalidCredential)
	}
	if isReuse(c.password) || slices.ContainsFunc(c.history, func(e PasswordHistoryEntry) bool { return isReuse(e.Hash) }) {
		return ErrPasswordReused
	}

	c.history = slices.Insert(c.history, 0, PasswordHistoryEntry{Hash: c.password, CreatedAt: now})
	if len(c.history) > policy.HistoryDepth {
		c.history = slices.Clip(c.history[:policy.HistoryDepth])
	}
	c.password = newHash
	c.passwordCreatedAt = now
	c.passwordExpiresAt = policy.expiryFrom(now)
	c.forcePasswordChange = false
	return nil
}

func (c *Credential) lock(policy LockoutPolicy, triggerIP netip.Addr, now time.Time) {
	c.lockoutHistoryCount++
	c.lockedAt = &now
	if c.lockoutHistoryCount <= len(policy.TemporaryDurations) {
		until := now.Add(policy.TemporaryDurations[c.lockoutHistoryCount-1])
		c.lockoutStatus = LockoutTemporary
		c.lockedUntil = &until
	} else {
		c.lockoutStatus = LockoutPermanent
		c.lockedUntil = nil
	}
	c.record(AccountLocked{
		CredentialID:       c.id,
		IdentityID:         c.identity,
		LockoutType:        c.lockoutStatus,
		LockedUntil:        copyTime(c.lockedUntil),
		TriggerIP:          triggerIP,
		FailedAttemptCount: c.failedAttemptCount,
		At:                 now,
	})
}

func (c *Credential) unlock(by IdentityRef, at time.Time) {
	previous := c.lockoutStatus
	c.lockoutStatus = LockoutUnlocked
	c.lockedAt = nil
	c.lockedUntil = nil
	c.failedAttemptCount = 0
	c.lastFailedAt = nil
	c.record(AccountUnlocked{
		CredentialID:        c.id,
		IdentityID:          c.identity,
		UnlockedBy:          by,
		PreviousLockoutType: previous,
		At:                  at,
	})
}

func (c *Credential) recordLoginFailed(attempt AttemptContext, reason LoginFailureReason, now time.Time) {
	c.record(LoginFailed{
		CredentialID:       c.id,
		IdentityID:         c.identity,
		CompanyCode:        attempt.CompanyCode,
		Reason:             reason,
		FailedAttemptCount: c.failedAttemptCount,
		IPAddress:          attempt.IP,
		UserAgent:          attempt.UserAgent,
		DeviceFingerprint:  attempt.DeviceFingerprint,
		At:                 now,
	})
}

func (c *Credential) record(e DomainEvent) { c.events = append(c.events, e) }

// CredentialSnapshot is the flat persistence shape of a credential
// (credentials + password_history tables, PRD §12).
type CredentialSnapshot struct {
	ID                  CredentialID
	IdentityID          IdentityRef
	Password            PasswordHash
	PasswordCreatedAt   time.Time
	PasswordExpiresAt   *time.Time
	ForcePasswordChange bool
	FailedAttemptCount  int
	LastFailedAt        *time.Time
	LockoutStatus       LockoutStatus
	LockedAt            *time.Time
	LockedUntil         *time.Time
	LockoutHistoryCount int
	History             []PasswordHistoryEntry // newest first
}

// Snapshot returns a copy of the credential's state for persistence.
func (c *Credential) Snapshot() CredentialSnapshot {
	return CredentialSnapshot{
		ID:                  c.id,
		IdentityID:          c.identity,
		Password:            c.password,
		PasswordCreatedAt:   c.passwordCreatedAt,
		PasswordExpiresAt:   copyTime(c.passwordExpiresAt),
		ForcePasswordChange: c.forcePasswordChange,
		FailedAttemptCount:  c.failedAttemptCount,
		LastFailedAt:        copyTime(c.lastFailedAt),
		LockoutStatus:       c.lockoutStatus,
		LockedAt:            copyTime(c.lockedAt),
		LockedUntil:         copyTime(c.lockedUntil),
		LockoutHistoryCount: c.lockoutHistoryCount,
		History:             slices.Clone(c.history),
	}
}

// RehydrateCredential rebuilds a credential from storage without recording
// events. It rejects snapshots that violate the aggregate's invariants.
func RehydrateCredential(snap CredentialSnapshot, policy CredentialPolicy) (*Credential, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	switch {
	case snap.ID == "" || snap.IdentityID == "":
		return nil, fmt.Errorf("%w: id and identity are required", ErrInvalidCredential)
	case snap.Password.IsZero():
		return nil, fmt.Errorf("%w: password is required", ErrInvalidCredential)
	case snap.PasswordCreatedAt.IsZero():
		return nil, fmt.Errorf("%w: password creation time is required", ErrInvalidCredential)
	case !snap.LockoutStatus.Valid():
		return nil, fmt.Errorf("%w: unknown lockout status %q", ErrInvalidCredential, snap.LockoutStatus)
	case snap.FailedAttemptCount < 0 || snap.LockoutHistoryCount < 0:
		return nil, fmt.Errorf("%w: negative counters", ErrInvalidCredential)
	case len(snap.History) > policy.HistoryDepth:
		return nil, fmt.Errorf("%w: history depth %d exceeds policy %d", ErrInvalidCredential, len(snap.History), policy.HistoryDepth)
	}

	switch snap.LockoutStatus {
	case LockoutUnlocked:
		if snap.LockedAt != nil || snap.LockedUntil != nil {
			return nil, fmt.Errorf("%w: unlocked credential carries lock timestamps", ErrInvalidCredential)
		}
	case LockoutTemporary:
		if snap.LockedAt == nil || snap.LockedUntil == nil || snap.LockoutHistoryCount < 1 {
			return nil, fmt.Errorf("%w: temporary lock needs locked_at, locked_until and a lockout count", ErrInvalidCredential)
		}
	case LockoutPermanent:
		if snap.LockedAt == nil || snap.LockedUntil != nil || snap.LockoutHistoryCount < 1 {
			return nil, fmt.Errorf("%w: permanent lock needs locked_at, no locked_until and a lockout count", ErrInvalidCredential)
		}
	}

	for _, e := range snap.History {
		if e.Hash.IsZero() {
			return nil, fmt.Errorf("%w: empty history entry", ErrInvalidCredential)
		}
	}

	return &Credential{
		id:                  snap.ID,
		identity:            snap.IdentityID,
		password:            snap.Password,
		passwordCreatedAt:   snap.PasswordCreatedAt.UTC(),
		passwordExpiresAt:   utcTime(snap.PasswordExpiresAt),
		forcePasswordChange: snap.ForcePasswordChange,
		failedAttemptCount:  snap.FailedAttemptCount,
		lastFailedAt:        utcTime(snap.LastFailedAt),
		lockoutStatus:       snap.LockoutStatus,
		lockedAt:            utcTime(snap.LockedAt),
		lockedUntil:         utcTime(snap.LockedUntil),
		lockoutHistoryCount: snap.LockoutHistoryCount,
		history:             slices.Clone(snap.History),
	}, nil
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func utcTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}
