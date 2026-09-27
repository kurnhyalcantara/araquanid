// Package usecase implements the Login application logic (FRD Functional
// Area 1). It depends only on internal/domain and the login feature's own
// repository ports — never on pgx/redis/grpc directly (usecase-clean
// depguard rule).
package usecase

import (
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
	"github.com/kurnhyalcantara/araquanid/internal/platform/passwordhash"
)

// RateLimitConfig mirrors config.RateLimit (FR-LOGIN-008).
type RateLimitConfig struct {
	IPMaxAttempts       int
	IPWindow            time.Duration
	IdentityMaxAttempts int
	IdentityWindow      time.Duration
}

// Config is the Login usecase's tunable policy, assembled by the container
// from config.Config.Auth.*.
type Config struct {
	Lockout            domain.LockoutPolicy
	CredentialPolicy   domain.CredentialPolicy
	SessionPolicy      domain.SessionPolicy
	ConcurrentPolicy   string // "ALLOW_ALL" | "LIMIT_N" | "SINGLE"
	ConcurrentMax      int
	MFASessionWindow   time.Duration
	ForcedChangeWindow time.Duration
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	Argon2id           passwordhash.Argon2idParams
	FingerprintVersion int
	RateLimit          RateLimitConfig
}

// Dependencies are the Login usecase's outbound ports and collaborators.
type Dependencies struct {
	UnitOfWork      repository.UnitOfWork
	Credentials     repository.CredentialRepository
	Devices         repository.DeviceRepository
	MFAFactors      repository.MFAFactorRepository
	LoginAttempts   repository.LoginAttemptRepository
	IdentityACL     repository.IdentityACL
	MFASessionStore repository.MFASessionStore
	RateLimiter     repository.RateLimiter
	TokenSigner     repository.TokenSigner

	Clock  func() time.Time
	NewID  func() string
	Logger *slog.Logger

	Config Config
}

// Usecase implements the Login application logic.
type Usecase struct {
	deps Dependencies
}

// New builds a Usecase. Clock/NewID/Logger default to time.Now/uuid.NewString/
// slog.Default when left zero.
func New(d Dependencies) *Usecase {
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.NewID == nil {
		d.NewID = uuid.NewString
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &Usecase{deps: d}
}
