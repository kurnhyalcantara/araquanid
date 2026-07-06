package domain_auth

import "time"

// LockoutStatus is the lockout state of a credential (FR-LOGIN-004).
type LockoutStatus string

const (
	LockoutUnlocked  LockoutStatus = "UNLOCKED"
	LockoutTemporary LockoutStatus = "LOCKED_TEMPORARY"
	LockoutPermanent LockoutStatus = "LOCKED_PERMANENT"
)

// PasswordAlgorithm identifies the hashing algorithm of a stored password
// (FR-LOGIN-005).
type PasswordAlgorithm string

const (
	PasswordArgon2id PasswordAlgorithm = "argon2id"
	PasswordBcrypt   PasswordAlgorithm = "bcrypt" // legacy, migration only
)

// AuthenticationResult is the outcome of a login or MFA step (FR-LOGIN-006).
type AuthenticationResult string

const (
	AuthCompleted              AuthenticationResult = "COMPLETED"
	AuthMFARequired            AuthenticationResult = "MFA_REQUIRED"
	AuthPasswordChangeRequired AuthenticationResult = "PASSWORD_CHANGE_REQUIRED"
)

// AAL is the NIST SP 800-63B Authenticator Assurance Level of a session
// (FR-SESSION-001).
type AAL string

const (
	AAL1 AAL = "AAL1"
	AAL2 AAL = "AAL2"
	AAL3 AAL = "AAL3"
)

// FactorType enumerates the supported MFA methods (FR-MFA-VERIFY-001).
type FactorType string

const (
	FactorTOTP         FactorType = "TOTP"
	FactorSMSOTP       FactorType = "SMS_OTP"
	FactorFIDO2        FactorType = "FIDO2"
	FactorRecoveryCode FactorType = "RECOVERY_CODE"
)

// FactorStatus is the lifecycle status of an MFA factor.
type FactorStatus string

const (
	FactorPending  FactorStatus = "PENDING"
	FactorActive   FactorStatus = "ACTIVE"
	FactorDisabled FactorStatus = "DISABLED"
	FactorRevoked  FactorStatus = "REVOKED"
)

// LoginOutcome classifies a persisted login attempt (FR-POST-AUTH-001).
type LoginOutcome string

const (
	OutcomeSucceeded              LoginOutcome = "SUCCEEDED"
	OutcomeFailedCredentials      LoginOutcome = "FAILED_CREDENTIALS"
	OutcomeFailedMFA              LoginOutcome = "FAILED_MFA"
	OutcomeFailedLocked           LoginOutcome = "FAILED_LOCKED"
	OutcomeFailedRateLimited      LoginOutcome = "FAILED_RATE_LIMITED"
	OutcomeFailedIdentityInactive LoginOutcome = "FAILED_IDENTITY_INACTIVE"
)

// IdentityStatus is the auth module's view of an identity's lifecycle status,
// sourced from the Identity Context (FR-LOGIN-003).
type IdentityStatus string

const (
	IdentityActive            IdentityStatus = "ACTIVE"
	IdentityInactive          IdentityStatus = "INACTIVE"
	IdentitySuspended         IdentityStatus = "SUSPENDED"
	IdentityPendingActivation IdentityStatus = "PENDING_ACTIVATION"
	IdentityDeleted           IdentityStatus = "DELETED"
)

// IdentityRef is the subset of Identity Context data the auth module consumes
// via its anti-corruption layer. The auth module never stores identity profile
// data; it holds only this reference for the duration of a request.
type IdentityRef struct {
	IdentityID  string
	Username    string
	DisplayName string
	Status      IdentityStatus
	CorporateID string
	MaskedPhone string
}

// IsActive reports whether the identity may authenticate.
func (r IdentityRef) IsActive() bool { return r.Status == IdentityActive }

// Credential holds the password and lockout state for an identity
// (credentials table; FR-LOGIN-004/005/009, FR-PWD-004).
type Credential struct {
	ID                  string
	IdentityID          string
	PasswordHash        string
	PasswordAlgorithm   PasswordAlgorithm
	PasswordVersion     int
	PasswordCreatedAt   time.Time
	PasswordExpiresAt   *time.Time
	ForcePasswordChange bool
	FailedAttemptCount  int
	LastFailedAt        *time.Time
	LockoutStatus       LockoutStatus
	LockedAt            *time.Time
	LockedUntil         *time.Time
	// LockoutHistoryCount is a cumulative lifetime counter used to determine the
	// lockout tier; it is never reset (FR-LOGIN-009).
	LockoutHistoryCount int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// LoginAttempt is an immutable audit record of a single authentication attempt
// (login_attempts table; FR-POST-AUTH-001, §15.2).
type LoginAttempt struct {
	ID                string
	IdentityID        *string
	IdentifierHash    string
	Outcome           LoginOutcome
	FailureReason     string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint *string
	AttemptedAt       time.Time
	SessionID         *string
	MFAFactorType     *FactorType
}

// MFAFactor is an enrolled multi-factor authentication method for an identity
// (mfa_factors table; FR-MFA-ENROLL/VERIFY). Sensitive material (secrets, keys)
// is stored encrypted and never leaves the repository layer in cleartext.
type MFAFactor struct {
	ID                  string
	IdentityID          string
	FactorType          FactorType
	Status              FactorStatus
	DisplayName         string
	EnrolledAt          *time.Time
	LastUsedAt          *time.Time
	LastUsedWindow      *int64
	TOTPSecretEncrypted []byte
	TOTPAlgorithm       string
	TOTPDigits          int
	TOTPPeriod          int
	FIDO2CredentialID   []byte
	FIDO2PublicKey      []byte
	FIDO2AAGUID         string
	FIDO2Counter        int64
	CreatedAt           time.Time
}

// MFAPendingOTP is a pending one-time password awaiting verification
// (mfa_pending_otps table; FR-MFA-VERIFY-003, FR-MFA-ENROLL-007).
type MFAPendingOTP struct {
	ID           string
	IdentityID   string
	OTPHash      string
	Purpose      string
	ExpiresAt    time.Time
	AttemptCount int
	IsUsed       bool
	UsedAt       *time.Time
	CreatedAt    time.Time
}

// MFARecoveryCode is a single-use recovery code hash for an MFA factor
// (mfa_recovery_codes table; FR-MFA-VERIFY-005).
type MFARecoveryCode struct {
	ID         string
	FactorID   string
	IdentityID string
	CodeHash   string
	IsUsed     bool
	UsedAt     *time.Time
	CreatedAt  time.Time
}

// MFASession is the transient state, held in Redis, that ties a credential
// verification to a pending MFA challenge (FR-LOGIN-010).
type MFASession struct {
	Token                string
	IdentityID           string
	CredentialVerifiedAt time.Time
	AvailableFactorIDs   []string
	FailedMFAAttempts    int
	ClientID             string
	DeviceFingerprint    string
	// Challenge is the FIDO2 challenge issued for this session, if any
	// (FR-MFA-VERIFY-006).
	Challenge string
}
