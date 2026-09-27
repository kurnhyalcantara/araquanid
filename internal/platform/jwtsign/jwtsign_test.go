package jwtsign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := NewSigner(Config{PrivateKeyPEM: string(pemBytes), Kid: "test-kid", Issuer: "https://auth.test"})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func TestSignAccessTokenClaimsAndKid(t *testing.T) {
	signer := testSigner(t)
	token, err := signer.SignAccessToken(AccessTokenClaims{
		Subject:     "identity-123",
		Audience:    []string{"web"},
		SessionID:   "sess-1",
		AAL:         "AAL1",
		DeviceID:    "device-1",
		CorporateID: "corp-1",
	}, 15*time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	parsed, err := jwt.ParseWithClaims(token, &accessTokenClaims{}, func(tok *jwt.Token) (any, error) {
		if tok.Header["kid"] != "test-kid" {
			t.Errorf("kid header = %v, want test-kid", tok.Header["kid"])
		}
		return &signer.key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	claims := parsed.Claims.(*accessTokenClaims)
	if claims.Subject != "identity-123" || claims.SessionID != "sess-1" || claims.AAL != "AAL1" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if claims.Scope != "" {
		t.Errorf("Scope should default to empty (BR-008: no role/permission claims), got %q", claims.Scope)
	}
}

func TestSignRestrictedTokenPurpose(t *testing.T) {
	signer := testSigner(t)
	token, err := signer.SignRestrictedToken("identity-123", "password_change", 5*time.Minute)
	if err != nil {
		t.Fatalf("SignRestrictedToken: %v", err)
	}

	parsed, err := jwt.ParseWithClaims(token, &restrictedClaims{}, func(tok *jwt.Token) (any, error) {
		return &signer.key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	claims := parsed.Claims.(*restrictedClaims)
	if claims.Purpose != "password_change" {
		t.Errorf("Purpose = %q, want password_change", claims.Purpose)
	}
}

func TestNewSignerRequiresKid(t *testing.T) {
	if _, err := NewSigner(Config{PrivateKeyPEM: "irrelevant"}); err == nil {
		t.Fatal("expected an error when Kid is empty")
	}
}

func TestNewSignerRequiresKeyMaterial(t *testing.T) {
	if _, err := NewSigner(Config{Kid: "k"}); err == nil {
		t.Fatal("expected an error when neither PrivateKeyPEM nor PrivateKeyPath is set")
	}
}
