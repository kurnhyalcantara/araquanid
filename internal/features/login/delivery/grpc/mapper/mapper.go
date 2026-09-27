// Package mapper holds pure functions translating between the generated
// proto types, this feature's dto, and the usecase's own input/result types.
package mapper

import (
	"net/netip"

	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/login/delivery/grpc/dto"
	"github.com/kurnhyalcantara/araquanid/internal/features/login/usecase"
)

// ToDTO maps the wire request to the validated-input shape.
func ToDTO(req *authv1.LoginRequest) dto.LoginInput {
	fp := req.GetDeviceFingerprint()
	return dto.LoginInput{
		Identifier:  req.GetIdentifier(),
		Password:    req.GetPassword(),
		ClientID:    req.GetClientId(),
		CompanyCode: req.GetCompanyCode(),
		DeviceFingerprint: dto.DeviceFingerprintInput{
			ScreenResolution: fp.GetScreenResolution(),
			Timezone:         fp.GetTimezone(),
			Platform:         fp.GetPlatform(),
			ColorDepth:       fp.GetColorDepth(),
			Language:         fp.GetLanguage(),
		},
	}
}

// ToUsecaseInput folds server-observed request context (client IP, headers)
// into the validated dto to build the usecase's input.
func ToUsecaseInput(in dto.LoginInput, ip netip.Addr, userAgent, acceptLanguage string) usecase.LoginInput {
	return usecase.LoginInput{
		Identifier:  in.Identifier,
		Password:    in.Password,
		ClientID:    in.ClientID,
		CompanyCode: in.CompanyCode,
		DeviceFingerprint: usecase.DeviceFingerprintInput{
			ScreenResolution: in.DeviceFingerprint.ScreenResolution,
			Timezone:         in.DeviceFingerprint.Timezone,
			Platform:         in.DeviceFingerprint.Platform,
			ColorDepth:       in.DeviceFingerprint.ColorDepth,
			Language:         in.DeviceFingerprint.Language,
		},
		IP:             ip,
		UserAgent:      userAgent,
		AcceptLanguage: acceptLanguage,
	}
}

// ToProtoResponse maps a successful usecase.LoginResult (COMPLETED,
// MFA_REQUIRED, or PASSWORD_CHANGE_REQUIRED) to the wire response. Business
// errors never reach this function — see the handler.
func ToProtoResponse(r *usecase.LoginResult) *authv1.LoginResponse {
	return &authv1.LoginResponse{
		AuthenticationResult:     authenticationResult(r.AuthenticationResult),
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

func authenticationResult(s string) authv1.AuthenticationResult {
	switch s {
	case "COMPLETED":
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_COMPLETED
	case "MFA_REQUIRED":
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_MFA_REQUIRED
	case "PASSWORD_CHANGE_REQUIRED":
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_PASSWORD_CHANGE_REQUIRED
	default:
		return authv1.AuthenticationResult_AUTHENTICATION_RESULT_UNSPECIFIED
	}
}

func aal(s string) authv1.Aal {
	switch s {
	case string(domain.AAL1):
		return authv1.Aal_AAL_AAL1
	case string(domain.AAL2):
		return authv1.Aal_AAL_AAL2
	case string(domain.AAL3):
		return authv1.Aal_AAL_AAL3
	default:
		return authv1.Aal_AAL_UNSPECIFIED
	}
}

func factorTypes(factors []domain.FactorType) []authv1.FactorType {
	out := make([]authv1.FactorType, 0, len(factors))
	for _, f := range factors {
		if ft, ok := factorType(f); ok {
			out = append(out, ft)
		}
	}
	return out
}

// factorType maps a domain.FactorType to the proto enum. domain.FactorPasskey
// has no proto equivalent yet (Passkey/passwordless login is an explicit
// Phase 2 PRD roadmap item, F-002) — such a factor is silently omitted from
// available_factors rather than failing the whole response.
func factorType(f domain.FactorType) (authv1.FactorType, bool) {
	switch f {
	case domain.FactorTOTP:
		return authv1.FactorType_FACTOR_TYPE_TOTP, true
	case domain.FactorSMSOTP:
		return authv1.FactorType_FACTOR_TYPE_SMS_OTP, true
	case domain.FactorFIDO2:
		return authv1.FactorType_FACTOR_TYPE_FIDO2, true
	default:
		return authv1.FactorType_FACTOR_TYPE_UNSPECIFIED, false
	}
}
