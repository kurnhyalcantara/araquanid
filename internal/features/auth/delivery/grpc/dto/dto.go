// Package dto defines the auth handler's request input structures, carrying the
// validation rules (FRD §12) applied before requests reach the usecase.
package dto

// DeviceFingerprintInput is the optional client-supplied fingerprint payload
// (FRD §12.2 device_fingerprint fields).
type DeviceFingerprintInput struct {
	UserAgent        string `validate:"max=512"`
	AcceptLanguage   string `validate:"max=64"`
	ScreenResolution string `validate:"omitempty,max=11"`
	Timezone         string `validate:"max=64"`
	Platform         string `validate:"max=128"`
	ColorDepth       int32  `validate:"gte=0"`
	Language         string `validate:"max=128"`
}

// LoginInput validates POST /api/v1/auth/login (FR-LOGIN-001, §12.2).
type LoginInput struct {
	Identifier        string                  `validate:"required,min=1,max=256"`
	Password          string                  `validate:"required,min=1,max=128"`
	ClientID          string                  `validate:"required,max=128"`
	DeviceFingerprint *DeviceFingerprintInput `validate:"omitempty"`
}

// FIDO2AssertionInput validates a WebAuthn assertion (FR-MFA-VERIFY-004).
type FIDO2AssertionInput struct {
	CredentialID      string `validate:"required"`
	ClientDataJSON    string `validate:"required"`
	AuthenticatorData string `validate:"required"`
	Signature         string `validate:"required"`
}

// VerifyMFAInput validates POST /api/v1/auth/mfa/verify (FR-MFA-VERIFY-001,
// §12.2). Code is required for TOTP, SMS_OTP, and RECOVERY_CODE; the FIDO2
// credential is required for FIDO2 (finer per-factor format checks are enforced
// in the usecase).
type VerifyMFAInput struct {
	MFASessionToken string               `validate:"required"`
	FactorType      string               `validate:"required,oneof=TOTP SMS_OTP FIDO2 RECOVERY_CODE"`
	Code            string               `validate:"required_unless=FactorType FIDO2"`
	FIDO2           *FIDO2AssertionInput `validate:"required_if=FactorType FIDO2"`
}
