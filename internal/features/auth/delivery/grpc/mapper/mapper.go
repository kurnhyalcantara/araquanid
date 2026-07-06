// Package mapper converts between transport types (the probopass auth
// contract), handler dtos, and usecase/domain types. Mappers are pure
// functions; transport types must not leak past this package into the usecase
// or domain.
package mapper

import (
	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"

	domain_auth "github.com/kurnhyalcantara/araquanid/internal/domain/auth"
	"github.com/kurnhyalcantara/araquanid/internal/features/auth/delivery/grpc/dto"
)

// ToLoginInputDTO maps the wire request to the validated handler dto.
func ToLoginInputDTO(req *authv1.LoginRequest) dto.LoginInput {
	in := dto.LoginInput{
		Identifier: req.GetIdentifier(),
		Password:   req.GetPassword(),
		ClientID:   req.GetClientId(),
	}
	if fp := req.GetDeviceFingerprint(); fp != nil {
		in.DeviceFingerprint = &dto.DeviceFingerprintInput{
			UserAgent:        fp.GetUserAgent(),
			AcceptLanguage:   fp.GetAcceptLanguage(),
			ScreenResolution: fp.GetScreenResolution(),
			Timezone:         fp.GetTimezone(),
			Platform:         fp.GetPlatform(),
			ColorDepth:       fp.GetColorDepth(),
			Language:         fp.GetLanguage(),
		}
	}
	return in
}

// ToLoginInput maps the validated dto (plus transport-observed attributes) into
// the usecase input.
func ToLoginInput(in dto.LoginInput, ipAddress, userAgent string) domain_auth.LoginInput {
	out := domain_auth.LoginInput{
		Identifier: in.Identifier,
		Password:   in.Password,
		ClientID:   in.ClientID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}
	if fp := in.DeviceFingerprint; fp != nil {
		out.DeviceFingerprint = &domain_auth.DeviceFingerprintInput{
			UserAgent:        fp.UserAgent,
			AcceptLanguage:   fp.AcceptLanguage,
			ScreenResolution: fp.ScreenResolution,
			Timezone:         fp.Timezone,
			Platform:         fp.Platform,
			ColorDepth:       fp.ColorDepth,
			Language:         fp.Language,
		}
	}
	return out
}

// ToVerifyMFAInputDTO maps the wire request to the validated handler dto.
func ToVerifyMFAInputDTO(req *authv1.VerifyMfaRequest) dto.VerifyMFAInput {
	in := dto.VerifyMFAInput{
		MFASessionToken: req.GetMfaSessionToken(),
		FactorType:      factorTypeName(req.GetFactorType()),
		Code:            req.GetCode(),
	}
	if c := req.GetCredential(); c != nil {
		in.FIDO2 = &dto.FIDO2AssertionInput{
			CredentialID:      c.GetCredentialId(),
			ClientDataJSON:    c.GetClientDataJson(),
			AuthenticatorData: c.GetAuthenticatorData(),
			Signature:         c.GetSignature(),
		}
	}
	return in
}

// ToVerifyMFAInput maps the validated dto (plus transport-observed attributes)
// into the usecase input.
func ToVerifyMFAInput(in dto.VerifyMFAInput, ipAddress, userAgent string) domain_auth.VerifyMFAInput {
	out := domain_auth.VerifyMFAInput{
		MFASessionToken: in.MFASessionToken,
		FactorType:      domain_auth.FactorType(in.FactorType),
		Code:            in.Code,
		IPAddress:       ipAddress,
		UserAgent:       userAgent,
	}
	if c := in.FIDO2; c != nil {
		out.FIDO2 = &domain_auth.FIDO2AssertionInput{
			CredentialID:      c.CredentialID,
			ClientDataJSON:    c.ClientDataJSON,
			AuthenticatorData: c.AuthenticatorData,
			Signature:         c.Signature,
		}
	}
	return out
}

// ToLoginResponse maps a usecase result to the wire login response.
func ToLoginResponse(r *domain_auth.LoginResult) *authv1.LoginResponse {
	if r == nil {
		return &authv1.LoginResponse{}
	}
	return &authv1.LoginResponse{
		AuthenticationResult:     authResult(r.AuthenticationResult),
		AccessToken:              r.AccessToken,
		TokenType:                r.TokenType,
		ExpiresIn:                r.ExpiresIn,
		RefreshToken:             r.RefreshToken,
		SessionId:                r.SessionID,
		Aal:                      aal(r.AAL),
		ForcePasswordChange:      r.ForcePasswordChange,
		MfaSessionToken:          r.MFASessionToken,
		AvailableFactors:         factorTypes(r.AvailableFactors),
		ForcedChangeSessionToken: r.ForcedChangeSessionToken,
	}
}

// ToVerifyMfaResponse maps a usecase result to the wire MFA verify response.
func ToVerifyMfaResponse(r *domain_auth.LoginResult) *authv1.VerifyMfaResponse {
	if r == nil {
		return &authv1.VerifyMfaResponse{}
	}
	return &authv1.VerifyMfaResponse{
		AuthenticationResult:    authResult(r.AuthenticationResult),
		AccessToken:             r.AccessToken,
		TokenType:               r.TokenType,
		ExpiresIn:               r.ExpiresIn,
		RefreshToken:            r.RefreshToken,
		SessionId:               r.SessionID,
		Aal:                     aal(r.AAL),
		LowRecoveryCodesWarning: r.LowRecoveryCodesWarning,
	}
}

func authResult(r domain_auth.AuthenticationResult) authv1.AuthenticationResult {
	switch r {
	case domain_auth.AuthCompleted:
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_COMPLETED
	case domain_auth.AuthMFARequired:
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_MFA_REQUIRED
	case domain_auth.AuthPasswordChangeRequired:
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_PASSWORD_CHANGE_REQUIRED
	default:
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_UNSPECIFIED
	}
}

func aal(a domain_auth.AAL) authv1.Aal {
	switch a {
	case domain_auth.AAL1:
		return authv1.Aal_AAL_AAL1
	case domain_auth.AAL2:
		return authv1.Aal_AAL_AAL2
	case domain_auth.AAL3:
		return authv1.Aal_AAL_AAL3
	default:
		return authv1.Aal_AAL_UNSPECIFIED
	}
}

func factorTypes(fs []domain_auth.FactorType) []authv1.FactorType {
	if len(fs) == 0 {
		return nil
	}
	out := make([]authv1.FactorType, 0, len(fs))
	for _, f := range fs {
		out = append(out, factorType(f))
	}
	return out
}

func factorType(f domain_auth.FactorType) authv1.FactorType {
	switch f {
	case domain_auth.FactorTOTP:
		return authv1.FactorType_FACTOR_TYPE_TOTP
	case domain_auth.FactorSMSOTP:
		return authv1.FactorType_FACTOR_TYPE_SMS_OTP
	case domain_auth.FactorFIDO2:
		return authv1.FactorType_FACTOR_TYPE_FIDO2
	case domain_auth.FactorRecoveryCode:
		return authv1.FactorType_FACTOR_TYPE_RECOVERY_CODE
	default:
		return authv1.FactorType_FACTOR_TYPE_UNSPECIFIED
	}
}

// factorTypeName renders the wire factor enum as the domain's string form, which
// the dto validates via `oneof` and the usecase input carries.
func factorTypeName(f authv1.FactorType) string {
	switch f {
	case authv1.FactorType_FACTOR_TYPE_TOTP:
		return string(domain_auth.FactorTOTP)
	case authv1.FactorType_FACTOR_TYPE_SMS_OTP:
		return string(domain_auth.FactorSMSOTP)
	case authv1.FactorType_FACTOR_TYPE_FIDO2:
		return string(domain_auth.FactorFIDO2)
	case authv1.FactorType_FACTOR_TYPE_RECOVERY_CODE:
		return string(domain_auth.FactorRecoveryCode)
	default:
		return ""
	}
}
