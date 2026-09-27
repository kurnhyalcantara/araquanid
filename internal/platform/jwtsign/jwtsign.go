// Package jwtsign issues RS256 JWTs with the claim set FR-SESSION-002
// requires (iss, sub, aud, iat, exp, jti, session_id, aal, device_id,
// corporate_id, scope) plus short-lived, purpose-scoped restricted tokens
// (e.g. the forced password-change session token, FR-LOGIN-006/BR-011).
//
// kingler's pkg/platform/jwt is HS256-only and signs only {user_id,
// session_id}, so it cannot carry this claim set or algorithm — this package
// is araquanid-local, shared under internal/platform because the future
// refresh/introspect/JWKS features need the exact same signer and keypair.
package jwtsign

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Config configures the signer. PrivateKeyPEM, when set, takes precedence
// (e.g. injected as a k8s Secret env value); otherwise PrivateKeyPath is
// read from disk (local dev — see `make dev-keys`).
type Config struct {
	PrivateKeyPEM  string
	PrivateKeyPath string
	Kid            string
	Issuer         string
}

// AccessTokenClaims is the caller-supplied subset of an access token's
// claims; iss/iat/exp/jti are set by the signer itself.
type AccessTokenClaims struct {
	Subject     string   // identity_id
	Audience    []string // resolved client identity (+ any configured extra audiences)
	SessionID   string
	AAL         string
	DeviceID    string
	CorporateID string
	// Scope is intentionally left empty by the login feature: BR-008
	// forbids role/permission claims on the Access Token.
	Scope string
}

type accessTokenClaims struct {
	jwt.RegisteredClaims
	SessionID   string `json:"session_id"`
	AAL         string `json:"aal"`
	DeviceID    string `json:"device_id,omitempty"`
	CorporateID string `json:"corporate_id,omitempty"`
	Scope       string `json:"scope"`
}

type restrictedClaims struct {
	jwt.RegisteredClaims
	Purpose string `json:"purpose"`
}

// Signer signs RS256 JWTs with a fixed key/kid.
type Signer struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
}

// NewSigner loads the RSA private key (from Config.PrivateKeyPEM, or
// Config.PrivateKeyPath as a fallback) and returns a ready-to-use Signer.
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.Kid == "" {
		return nil, errors.New("jwtsign: kid is required")
	}
	pemBytes, err := resolveKeyPEM(cfg)
	if err != nil {
		return nil, err
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("jwtsign: parse private key: %w", err)
	}
	return &Signer{key: key, kid: cfg.Kid, issuer: cfg.Issuer}, nil
}

func resolveKeyPEM(cfg Config) ([]byte, error) {
	if cfg.PrivateKeyPEM != "" {
		return []byte(cfg.PrivateKeyPEM), nil
	}
	if cfg.PrivateKeyPath == "" {
		return nil, errors.New("jwtsign: no private key configured (set PrivateKeyPEM or PrivateKeyPath)")
	}
	b, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("jwtsign: read private key file %s: %w", cfg.PrivateKeyPath, err)
	}
	return b, nil
}

func (s *Signer) sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("jwtsign: sign: %w", err)
	}
	return signed, nil
}

// SignAccessToken issues a full access token (FR-SESSION-002).
func (s *Signer) SignAccessToken(c AccessTokenClaims, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   c.Subject,
			Audience:  c.Audience,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
		SessionID:   c.SessionID,
		AAL:         c.AAL,
		DeviceID:    c.DeviceID,
		CorporateID: c.CorporateID,
		Scope:       c.Scope,
	}
	return s.sign(claims)
}

// SignRestrictedToken issues a short-TTL JWT scoped by a "purpose" claim
// (e.g. "password_change"). Enforcing that a restricted token is only
// accepted at its intended endpoint (BR-011) is that endpoint's
// responsibility, not the signer's — Login only ever issues these tokens.
func (s *Signer) SignRestrictedToken(subject, purpose string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := restrictedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
		Purpose: purpose,
	}
	return s.sign(claims)
}
