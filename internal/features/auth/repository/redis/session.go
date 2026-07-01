// Package redis is the Redis adapter for the auth feature's transient MFA
// session store (FR-LOGIN-010/011).
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
	"github.com/kurnhyalcantara/araquanid/internal/features/auth/repository"
)

// mfaSessionStore stores in-flight MFA challenge state under an opaque token
// with a bounded TTL (the MFA session window). The value is an opaque random
// token, never a JWT (FR-LOGIN-010).
type mfaSessionStore struct {
	client *redislib.Client
	ttl    time.Duration
}

// NewMFASessionStore returns a Redis-backed MFA session store. ttl is the MFA
// session window (auth.session.mfa_session_window).
func NewMFASessionStore(client *redislib.Client, ttl time.Duration) repository.MFASessionStore {
	return &mfaSessionStore{client: client, ttl: ttl}
}

func sessionKey(token string) string { return "mfa_session:" + token }

func (s *mfaSessionStore) Get(ctx context.Context, token string) (*domain.MFASession, error) {
	data, err := s.client.Get(ctx, sessionKey(token)).Bytes()
	if errors.Is(err, redislib.Nil) {
		return nil, domain.ErrMFASessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("auth repository: get mfa session: %w", err)
	}
	var sess domain.MFASession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("auth repository: decode mfa session: %w", err)
	}
	return &sess, nil
}

func (s *mfaSessionStore) Save(ctx context.Context, sess *domain.MFASession) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("auth repository: encode mfa session: %w", err)
	}
	if err := s.client.Set(ctx, sessionKey(sess.Token), data, s.ttl).Err(); err != nil {
		return fmt.Errorf("auth repository: save mfa session: %w", err)
	}
	return nil
}

func (s *mfaSessionStore) Delete(ctx context.Context, token string) error {
	if err := s.client.Del(ctx, sessionKey(token)).Err(); err != nil {
		return fmt.Errorf("auth repository: delete mfa session: %w", err)
	}
	return nil
}
