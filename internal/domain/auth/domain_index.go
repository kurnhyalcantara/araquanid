package domain_auth

import (
	"time"
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
	FactorType      FactorType
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
	AuthenticationResult     AuthenticationResult
	AccessToken              string
	TokenType                string
	ExpiresIn                int64
	RefreshToken             string
	SessionID                string
	AAL                      AAL
	ForcePasswordChange      bool
	MFASessionToken          string
	AvailableFactors         []FactorType
	ForcedChangeSessionToken string
	LowRecoveryCodesWarning  bool
}
