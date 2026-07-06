package domain_auth

import "errors"

// Authentication Module domain errors. These are the pure, transport-agnostic
// signals raised by the auth feature's usecase and repositories; the delivery
// layer maps them to app errors and, ultimately, RFC 7807 responses.
var (
	// ErrCredentialNotFound is returned when no credential exists for an identity.
	ErrCredentialNotFound = errors.New("credential not found")
	// ErrIdentityNotFound is returned when an identifier resolves to no identity.
	ErrIdentityNotFound = errors.New("identity not found")
	// ErrIdentityInactive is returned when the resolved identity is not ACTIVE.
	ErrIdentityInactive = errors.New("identity is not active")
	// ErrInvalidCredentials is the generic credential-verification failure.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrAccountLocked is returned when a credential is temporarily or
	// permanently locked out.
	ErrAccountLocked = errors.New("account is locked")
	// ErrMFASessionInvalid is returned when an MFA session token is unknown or
	// expired.
	ErrMFASessionInvalid = errors.New("mfa session is invalid or expired")
	// ErrInvalidMFACode is the generic MFA-verification failure.
	ErrInvalidMFACode = errors.New("invalid mfa code")
	// ErrMFAFactorNotFound is returned when the requested factor is absent or
	// inactive.
	ErrMFAFactorNotFound = errors.New("mfa factor not found")
)
