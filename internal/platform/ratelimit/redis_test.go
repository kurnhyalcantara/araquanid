package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redislib "github.com/redis/go-redis/v9"
)

func newTestLimiter(t *testing.T) *Limiter {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redislib.NewClient(&redislib.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb)
}

func TestAllowUnderLimit(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	for i := range 3 {
		allowed, _, err := l.Allow(ctx, "key", 3, time.Minute)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !allowed {
			t.Fatalf("attempt %d should be allowed (max 3)", i+1)
		}
	}
}

func TestAllowExceedsLimit(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	for range 3 {
		if _, _, err := l.Allow(ctx, "key", 3, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}

	allowed, retryAfter, err := l.Allow(ctx, "key", 3, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if allowed {
		t.Fatal("4th attempt should be denied (max 3)")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0", retryAfter)
	}
}

func TestAllowIsolatedByKey(t *testing.T) {
	l := newTestLimiter(t)
	ctx := context.Background()

	for range 3 {
		if _, _, err := l.Allow(ctx, "key-a", 3, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	allowed, _, err := l.Allow(ctx, "key-b", 3, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !allowed {
		t.Fatal("a different key should have its own independent counter")
	}
}
