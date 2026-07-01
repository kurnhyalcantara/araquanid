// Package usecase implements the auth feature's application logic. It depends
// only on the domain, the repository ports, and shared packages — never on
// transport (gen/) or infrastructure drivers.
//
// This slice currently delivers the callable contract for Functional Area 1
// (Login & Credential Verification): the method surface, wiring, and inputs are
// in place, while the credential-verification and MFA logic is deferred (each
// method returns a not-implemented error). The TODOs reference the governing
// FRD requirements.
package usecase

import (
	"context"
	"time"

	"github.com/kurnhyalcantara/kingler/pkg/apperror"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/auth/repository"
)

// Config carries the Authentication Module knobs the usecase needs. The
// container maps config.Auth into this usecase-local struct so the usecase does
// not depend on the application config package (FRD §16).
type Config struct {
	LockoutThreshold      int
	LockoutWindow         time.Duration
	LockoutTier1Duration  time.Duration
	LockoutTier2Duration  time.Duration
	MFASessionWindow      time.Duration
	AccessTTL             time.Duration
	RecoveryCodeLowThresh int
}

// DeviceFingerprintInput is the client-supplied fingerprint payload
// (FR-DEVICE-001). The server combines it with observed request attributes.
type DeviceFingerprintInput struct {
	UserAgent        string
	AcceptLanguage   string
	ScreenResolution string
	Timezone         string
	Platform         string
	ColorDepth       int32
	Language         string
}

// LoginInput is the resolved input to a login attempt. Transport-observed
// attributes (IP, user agent) are carried alongside the request body fields.
type LoginInput struct {
	Identifier        string
	Password          string
	ClientID          string
	DeviceFingerprint *DeviceFingerprintInput
	IPAddress         string
	UserAgent         string
}

// VerifyMFAInput is the input to an MFA verification step.
type VerifyMFAInput struct {
	MFASessionToken string
	FactorType      domain.FactorType
	Code            string
	FIDO2           *FIDO2AssertionInput
	IPAddress       string
	UserAgent       string
}

// FIDO2AssertionInput is a WebAuthn assertion response (FR-MFA-VERIFY-004).
type FIDO2AssertionInput struct {
	CredentialID      string
	ClientDataJSON    string
	AuthenticatorData string
	Signature         string
}

// LoginResult is the outcome of a login or MFA step, mapped to the transport
// response by the delivery layer (FR-POST-AUTH-002, FR-LOGIN-010, FR-PWD-009).
type LoginResult struct {
	AuthenticationResult     domain.AuthenticationResult
	AccessToken              string
	TokenType                string
	ExpiresIn                int64
	RefreshToken             string
	SessionID                string
	AAL                      domain.AAL
	ForcePasswordChange      bool
	MFASessionToken          string
	AvailableFactors         []domain.FactorType
	ForcedChangeSessionToken string
	LowRecoveryCodesWarning  bool
}

// Usecase is the auth feature's application-logic port consumed by the handler.
type Usecase interface {
	// Login verifies credentials and returns the next step (completed, MFA
	// required, or password change required) per the FR-LOGIN-006 decision tree.
	Login(ctx context.Context, in LoginInput) (*LoginResult, error)
	// VerifyMFA verifies a second-factor challenge for an in-flight MFA session
	// (FR-MFA-VERIFY-*).
	VerifyMFA(ctx context.Context, in VerifyMFAInput) (*LoginResult, error)
}

type authUsecase struct {
	credentials repository.CredentialRepository
	attempts    repository.LoginAttemptRepository
	mfa         repository.MFARepository
	mfaSessions repository.MFASessionStore
	identity    repository.IdentityACL
	cfg         Config
	now         func() time.Time
}

// New constructs the auth usecase from its repository ports and configuration.
func New(
	credentials repository.CredentialRepository,
	attempts repository.LoginAttemptRepository,
	mfa repository.MFARepository,
	mfaSessions repository.MFASessionStore,
	identity repository.IdentityACL,
	cfg Config,
) Usecase {
	return &authUsecase{
		credentials: credentials,
		attempts:    attempts,
		mfa:         mfa,
		mfaSessions: mfaSessions,
		identity:    identity,
		cfg:         cfg,
		now:         time.Now,
	}
}

func (u *authUsecase) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	// TODO(FR-LOGIN-002..012, FR-POST-AUTH-*): rate-limit (FR-LOGIN-008),
	// resolve the identifier via the Identity ACL (FR-LOGIN-002), enforce the
	// identity status and lockout pre-checks (FR-LOGIN-003/004), verify the
	// password with a timing-consistent dummy hash on miss (FR-LOGIN-005/007),
	// evaluate the force-change / expiry / MFA decision tree (FR-LOGIN-006),
	// and persist the LoginAttempt (FR-POST-AUTH-001).
	return nil, apperror.New(apperror.CodeInternal, "login not implemented")
}

func (u *authUsecase) VerifyMFA(ctx context.Context, in VerifyMFAInput) (*LoginResult, error) {
	// TODO(FR-MFA-VERIFY-001..006): load the MFA session (FR-LOGIN-011), verify
	// the submitted factor (TOTP/SMS OTP/FIDO2/recovery code), enforce replay and
	// attempt limits, then create the session on success (FR-SESSION-001).
	return nil, apperror.New(apperror.CodeInternal, "mfa verification not implemented")
}
