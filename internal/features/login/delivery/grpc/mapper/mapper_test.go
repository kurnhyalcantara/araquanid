package mapper

import (
	"net/netip"
	"testing"

	authv1 "github.com/kurnhyalcantara/probopass/gen/go/probopass/auth/v1"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/login/usecase"
)

func TestToDTO(t *testing.T) {
	req := &authv1.LoginRequest{
		Identifier:  "john.smith",
		Password:    "secret",
		ClientId:    "web",
		CompanyCode: "acme01",
		DeviceFingerprint: &authv1.DeviceFingerprint{
			ScreenResolution: "1920x1080",
			Timezone:         "Asia/Jakarta",
			Platform:         "Win32",
			ColorDepth:       24,
			Language:         "en-US",
		},
	}
	got := ToDTO(req)
	if got.Identifier != "john.smith" || got.ClientID != "web" || got.CompanyCode != "acme01" {
		t.Errorf("unexpected dto: %+v", got)
	}
	if got.DeviceFingerprint.ScreenResolution != "1920x1080" {
		t.Errorf("device fingerprint not mapped: %+v", got.DeviceFingerprint)
	}
}

func TestToDTONilFingerprint(t *testing.T) {
	req := &authv1.LoginRequest{Identifier: "john.smith", Password: "secret", ClientId: "web"}
	got := ToDTO(req) // must not panic on a nil DeviceFingerprint
	if got.DeviceFingerprint.ScreenResolution != "" {
		t.Errorf("expected zero-value fingerprint, got %+v", got.DeviceFingerprint)
	}
}

func TestToProtoResponseCompleted(t *testing.T) {
	resp := ToProtoResponse(&usecase.LoginResult{
		AuthenticationResult: "COMPLETED",
		AccessToken:          "at",
		TokenType:            "Bearer",
		ExpiresIn:            900,
		RefreshToken:         "rt",
		SessionID:            "sess-1",
		AAL:                  "AAL1",
	})
	if resp.AuthenticationResult != authv1.AuthenticationResult_AUTHENTICATION_RESULT_COMPLETED {
		t.Errorf("authentication_result = %v", resp.AuthenticationResult)
	}
	if resp.Aal != authv1.Aal_AAL_AAL1 {
		t.Errorf("aal = %v", resp.Aal)
	}
	if resp.AccessToken != "at" || resp.RefreshToken != "rt" || resp.SessionId != "sess-1" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestToProtoResponseMFARequiredOmitsUnmappableFactor(t *testing.T) {
	resp := ToProtoResponse(&usecase.LoginResult{
		AuthenticationResult: "MFA_REQUIRED",
		MFASessionToken:      "tok",
		AvailableFactors:     []domain.FactorType{domain.FactorTOTP, domain.FactorPasskey, domain.FactorSMSOTP},
	})
	if resp.AuthenticationResult != authv1.AuthenticationResult_AUTHENTICATION_RESULT_MFA_REQUIRED {
		t.Errorf("authentication_result = %v", resp.AuthenticationResult)
	}
	// FactorPasskey has no proto equivalent (Phase 2 roadmap item) and must
	// be silently dropped, not turned into FACTOR_TYPE_UNSPECIFIED.
	want := []authv1.FactorType{authv1.FactorType_FACTOR_TYPE_TOTP, authv1.FactorType_FACTOR_TYPE_SMS_OTP}
	if len(resp.AvailableFactors) != len(want) {
		t.Fatalf("available_factors = %v, want %v", resp.AvailableFactors, want)
	}
	for i, f := range want {
		if resp.AvailableFactors[i] != f {
			t.Errorf("available_factors[%d] = %v, want %v", i, resp.AvailableFactors[i], f)
		}
	}
}

func TestToUsecaseInput(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.1")
	in := ToUsecaseInput(ToDTO(&authv1.LoginRequest{Identifier: "a", Password: "b", ClientId: "web"}), ip, "ua", "en-US")
	if in.IP != ip || in.UserAgent != "ua" || in.AcceptLanguage != "en-US" {
		t.Errorf("server-observed context not folded in: %+v", in)
	}
}
