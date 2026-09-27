// Package redis is the Redis adapter for the login feature's MFA session
// store (FR-LOGIN-010).
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/kurnhyalcantara/araquanid/internal/features/login/repository"
)

const keyPrefix = "mfa_session:"

type mfaSessionStore struct {
	rdb *redislib.Client
}

// NewMFASessionStore builds a repository.MFASessionStore over an existing
// Redis client.
func NewMFASessionStore(rdb *redislib.Client) repository.MFASessionStore {
	return &mfaSessionStore{rdb: rdb}
}

// state is the JSON shape stored at mfa_session:{token} (FR-LOGIN-010).
type state struct {
	IdentityID           string   `json:"identity_id"`
	CredentialVerifiedAt string   `json:"credential_verified_at"`
	AvailableFactorIDs   []string `json:"available_factor_ids"`
	FailedMFAAttempts    int      `json:"failed_mfa_attempts"`
	ClientID             string   `json:"client_id"`
	DeviceFingerprint    string   `json:"device_fingerprint"`
}

func (s *mfaSessionStore) Create(ctx context.Context, token string, in repository.MFASessionState, ttl time.Duration) error {
	factorIDs := make([]string, len(in.AvailableFactors))
	for i, f := range in.AvailableFactors {
		factorIDs[i] = string(f)
	}
	payload, err := json.Marshal(state{
		IdentityID:           in.IdentityID,
		CredentialVerifiedAt: in.CredentialVerifiedAt.UTC().Format(time.RFC3339),
		AvailableFactorIDs:   factorIDs,
		FailedMFAAttempts:    in.FailedMFAAttempts,
		ClientID:             in.ClientID,
		DeviceFingerprint:    in.DeviceFingerprint,
	})
	if err != nil {
		return fmt.Errorf("login/redis: marshal mfa session state: %w", err)
	}
	if err := s.rdb.Set(ctx, keyPrefix+token, payload, ttl).Err(); err != nil {
		return fmt.Errorf("login/redis: create mfa session: %w", err)
	}
	return nil
}
