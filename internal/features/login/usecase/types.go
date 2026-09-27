package usecase

import (
	"net/netip"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

// DeviceFingerprintInput is the client-supplied subset of FR-DEVICE-001's
// fingerprint components (user_agent/accept_language are server-observed
// headers, carried separately on LoginInput, not here — see fingerprint.go).
type DeviceFingerprintInput struct {
	ScreenResolution string
	Timezone         string
	Platform         string
	ColorDepth       int32
	Language         string
}

// LoginInput is the delivery-agnostic input to Login.
type LoginInput struct {
	Identifier        string
	Password          string
	ClientID          string
	CompanyCode       string
	DeviceFingerprint DeviceFingerprintInput

	IP             netip.Addr
	UserAgent      string
	AcceptLanguage string
}

// LoginResult is returned only for the three non-error outcomes
// (COMPLETED/MFA_REQUIRED/PASSWORD_CHANGE_REQUIRED, FR-LOGIN-006). Business
// errors (invalid credentials, locked, rate limited) are returned as an
// *apperror.Error instead — see login.go.
type LoginResult struct {
	AuthenticationResult string // "COMPLETED" | "MFA_REQUIRED" | "PASSWORD_CHANGE_REQUIRED"

	// Set when AuthenticationResult == COMPLETED.
	AccessToken         string
	TokenType           string
	ExpiresIn           int64
	RefreshToken        string
	SessionID           string
	AAL                 string
	ForcePasswordChange bool

	// Set when AuthenticationResult == MFA_REQUIRED.
	MFASessionToken  string
	AvailableFactors []domain.FactorType

	// Set when AuthenticationResult == PASSWORD_CHANGE_REQUIRED.
	ForcedChangeSessionToken string
}
