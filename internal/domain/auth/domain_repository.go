package domain_auth

import (
	"context"
)

// CredentialRepository is the store of password credentials and their lockout
// state (credentials table; FR-LOGIN-004/005/007/009).
type CredentialRepository interface {
	// GetByIdentityID loads the credential for an identity, or
	// domain.ErrCredentialNotFound.
	GetByIdentityID(ctx context.Context, identityID string) (*Credential, error)
	// Update persists mutations to lockout/attempt/password fields.
	Update(ctx context.Context, c *Credential) error
}

// LoginAttemptRepository is the append-only audit store of authentication
// attempts (login_attempts table; FR-POST-AUTH-001, §15.2). It is INSERT-only.
type LoginAttemptRepository interface {
	Create(ctx context.Context, a *LoginAttempt) error
}

// MFARepository is the store of MFA factors and their verification artifacts
// (mfa_factors, mfa_pending_otps, mfa_recovery_codes; FR-MFA-VERIFY-*).
type MFARepository interface {
	// ListActiveFactors returns the identity's active factors (no secrets in
	// cleartext beyond what verification requires).
	ListActiveFactors(ctx context.Context, identityID string) ([]*MFAFactor, error)
	// GetFactorByCredentialID looks up a FIDO2 factor by its raw credential id.
	GetFactorByCredentialID(ctx context.Context, identityID string, credentialID []byte) (*MFAFactor, error)
	// UpdateFactor persists mutations (counters, last-used windows/timestamps).
	UpdateFactor(ctx context.Context, f *MFAFactor) error
	// GetPendingOTP loads an unused, unexpired OTP for the identity/purpose.
	GetPendingOTP(ctx context.Context, identityID, purpose string) (*MFAPendingOTP, error)
	// UpdatePendingOTP persists mutations (attempt count, used flag).
	UpdatePendingOTP(ctx context.Context, o *MFAPendingOTP) error
	// ListRecoveryCodes returns the identity's unused recovery codes.
	ListRecoveryCodes(ctx context.Context, identityID string) ([]*MFARecoveryCode, error)
	// MarkRecoveryCodeUsed consumes a recovery code.
	MarkRecoveryCodeUsed(ctx context.Context, id string) error
}

// MFASessionStore is the transient, TTL-bounded store (Redis) of in-flight MFA
// challenge state keyed by an opaque token (FR-LOGIN-010/011).
type MFASessionStore interface {
	Get(ctx context.Context, token string) (*MFASession, error)
	Save(ctx context.Context, s *MFASession) error
	Delete(ctx context.Context, token string) error
}

// IdentityACL is the anti-corruption layer over the Identity Context. It is the
// auth module's only path to identity data; the auth module never stores
// identity profiles (FR-LOGIN-002/003, FR-MFA-ENROLL-006).
type IdentityACL interface {
	// Resolve maps a submitted identifier to an identity reference. found is
	// false (with a nil ref) when no identity matches.
	Resolve(ctx context.Context, identifier string) (ref *IdentityRef, found bool, err error)
	// Get returns identity display/status data by id.
	Get(ctx context.Context, identityID string) (*IdentityRef, error)
}
