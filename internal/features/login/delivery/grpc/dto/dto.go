// Package dto holds the login feature's handler input structs, tagged for
// internal/validator (go-playground/validator under the hood).
package dto

// DeviceFingerprintInput is the client-supplied subset of FR-DEVICE-001's
// fingerprint components (see internal/features/login/usecase/fingerprint.go
// for the full canonical hash, which also folds in server-observed headers).
type DeviceFingerprintInput struct {
	ScreenResolution string `validate:"omitempty,max=32"`
	Timezone         string `validate:"omitempty,max=64"`
	Platform         string `validate:"omitempty,max=64"`
	ColorDepth       int32  `validate:"omitempty,min=0"`
	Language         string `validate:"omitempty,max=35"`
}

// LoginInput is the validated shape of a Login request (FR-LOGIN-001,
// §12.2). Password has no max tag: BR-001 truncates rather than rejects an
// over-length password.
type LoginInput struct {
	Identifier        string `validate:"required,min=3,max=256"`
	Password          string `validate:"required"`
	ClientID          string `validate:"required,max=128"`
	CompanyCode       string `validate:"omitempty,max=64"`
	DeviceFingerprint DeviceFingerprintInput
}
