// Package repository declares the login feature's outbound ports. The
// usecase depends only on these interfaces (never on pgx/redis/grpc
// directly, enforced by the usecase-clean depguard rule), so every write
// this feature makes goes through UnitOfWork.Execute and commits atomically
// with the outbox rows recording it.
package repository

import (
	"context"
	"time"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/platform/jwtsign"
)

// ResolvedIdentity is the Identity Context's answer to a resolve call.
type ResolvedIdentity struct {
	IdentityID  string
	Status      string // "ACTIVE" | "INACTIVE" | "SUSPENDED" | "PENDING_ACTIVATION" | "DELETED"
	CorporateID string
}

// IdentityACL resolves login identifiers against the Identity bounded
// context (a separate service; this is an anti-corruption-layer port).
type IdentityACL interface {
	// ResolveIdentity returns (nil, false, nil) when the identifier/company
	// code combination is not found — never an error for "not found".
	ResolveIdentity(ctx context.Context, identifier, companyCode string) (*ResolvedIdentity, bool, error)
}

// CredentialRepository is a read-only lookup; all writes go through
// TxCredentials inside a UnitOfWork transaction.
type CredentialRepository interface {
	// FindByIdentity returns domain.ErrCredentialNotFound when no credential
	// exists for identityID.
	FindByIdentity(ctx context.Context, identityID string) (*domain.Credential, error)
}

// RegisteredDevice is the read shape used for the FR-DEVICE-002 lookup.
type RegisteredDevice struct {
	ID          string
	TrustStatus string
	LastSeenAt  time.Time
}

// DeviceRepository is a read-only lookup; registration/touch go through
// TxDevices inside a UnitOfWork transaction.
type DeviceRepository interface {
	// FindByFingerprint returns (nil, nil) when no non-revoked device
	// matches — never an error for "not found".
	FindByFingerprint(ctx context.Context, identityID, fingerprintHash string) (*RegisteredDevice, error)
}

// MFAFactorRepository answers the two read-only MFA-factor questions this
// feature needs (BR-003's voluntary-enrollment condition, and FR-LOGIN-010's
// available-factors list). Factor *management* (enroll/disable/list-for-UI)
// is a separate, out-of-scope feature.
type MFAFactorRepository interface {
	ListActiveFactorTypes(ctx context.Context, identityID string) ([]domain.FactorType, error)
	HasActiveFactor(ctx context.Context, identityID string) (bool, error)
}

// LoginAttemptRecord is one row of the append-only login_attempts audit
// trail (FR-POST-AUTH-001). The table is INSERT-only.
type LoginAttemptRecord struct {
	IdentityID        *string // nil when unresolved (rate-limited / not found)
	IdentifierHash    string  // SHA-256 of the raw submitted identifier, never the plaintext
	Outcome           string
	FailureReason     string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	SessionID         *string // set only when Outcome is SUCCEEDED
	MFAFactorType     string
	AttemptedAt       time.Time
}

// LoginAttemptRepository is used both standalone (rate-limited/not-found
// paths, which never enter a transaction) and inside a UnitOfWork.
type LoginAttemptRepository interface {
	Record(ctx context.Context, a LoginAttemptRecord) error
}

// RateLimiter is satisfied structurally by *internal/platform/ratelimit.Limiter.
type RateLimiter interface {
	Allow(ctx context.Context, key string, max int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

// MFASessionState is the Redis-held state for an in-flight MFA challenge
// (FR-LOGIN-010). It is deliberately opaque to the client — never a JWT.
type MFASessionState struct {
	IdentityID           string
	CredentialVerifiedAt time.Time
	AvailableFactors     []domain.FactorType
	FailedMFAAttempts    int
	ClientID             string
	DeviceFingerprint    string
}

// MFASessionStore holds MFA session state; the future VerifyMfa feature
// reads and consumes it, this feature only ever creates it.
type MFASessionStore interface {
	Create(ctx context.Context, token string, s MFASessionState, ttl time.Duration) error
}

// TokenSigner is satisfied structurally by *internal/platform/jwtsign.Signer.
type TokenSigner interface {
	SignAccessToken(c jwtsign.AccessTokenClaims, ttl time.Duration) (string, error)
	SignRestrictedToken(subject, purpose string, ttl time.Duration) (string, error)
}

// TxRepositories are the sub-ports available inside a UnitOfWork.Execute
// closure.
type TxRepositories struct {
	Credentials   TxCredentials
	Sessions      TxSessions
	RefreshTokens TxRefreshTokens
	Devices       TxDevices
	LoginAttempts LoginAttemptRepository
	Outbox        TxOutbox
}

// UnitOfWork hides the transaction boundary behind a closure so the usecase
// never imports pgx directly.
type UnitOfWork interface {
	Execute(ctx context.Context, fn func(ctx context.Context, r TxRepositories) error) error
}

type TxCredentials interface {
	Save(ctx context.Context, c *domain.Credential) error
}

// TxSessions covers session creation and the FR-LOGIN-012 concurrent-session
// policy (count/list/evict), all inside one transaction so eviction and the
// new session's creation are race-free.
type TxSessions interface {
	// Create persists s. clientID is not a domain invariant (see
	// domain.SessionSnapshot) — it is pure persistence bookkeeping needed to
	// scope the concurrent-session queries below.
	Create(ctx context.Context, s *domain.AuthenticationSession, clientID string) error
	Revoke(ctx context.Context, s *domain.AuthenticationSession) error
	CountActive(ctx context.Context, identityID, clientID string) (int, error)
	FindOldestActive(ctx context.Context, identityID, clientID string) (*domain.AuthenticationSession, error)
	ListActive(ctx context.Context, identityID, clientID string) ([]*domain.AuthenticationSession, error)
}

// RefreshTokenRecord is one row of refresh_tokens (FR-SESSION-003).
type RefreshTokenRecord struct {
	FamilyID  string
	TokenHash string
	ClientID  string
	IssuerIP  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type TxRefreshTokens interface {
	CreateFamily(ctx context.Context, familyID, sessionID, identityID string) error
	CreateToken(ctx context.Context, r RefreshTokenRecord) error
}

// TxDevices covers the FR-DEVICE-002 write path (registration/touch); the
// read-only lookup used for the BR-003 MFA decision is DeviceRepository.
type TxDevices interface {
	// Register returns ("", nil) when a REVOKED row already occupies the
	// unique (identity_id, fingerprint_hash) key (BR-012) — not an error;
	// the caller treats the device as still unrecognized.
	Register(ctx context.Context, identityID, fingerprintHash string, fingerprintVersion int, displayName, registrationIP string, now time.Time) (id string, err error)
	Touch(ctx context.Context, deviceID string, at time.Time) error
}

// TxOutbox appends domain events to the transactional outbox
// (internal/platform/outbox) inside the same transaction as the aggregate
// state they describe (PRD §10.4).
type TxOutbox interface {
	Append(ctx context.Context, events []domain.DomainEvent) error
}
