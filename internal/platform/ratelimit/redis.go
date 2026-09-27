// Package ratelimit implements FR-LOGIN-008's fixed-window rate limiting on
// top of Redis. It is a shared platform package (not nested in the login
// feature) since MFA-resend and password-reset rate limits will reuse it.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	redislib "github.com/redis/go-redis/v9"
)

// allowScript implements an atomic fixed-window counter: increment, set the
// window's expiry only on the first hit, and return both the new count and
// the key's remaining TTL in one round trip.
//
// Fixed-window, not a sliding log: simpler, matches the FRD's "N per window"
// phrasing exactly; a burst at the window boundary can momentarily allow up
// to ~2x max, an accepted trade-off over a heavier sliding-window-log design.
const allowScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
	redis.call("EXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("TTL", KEYS[1])
return {current, ttl}
`

// Limiter is a Redis-backed fixed-window rate limiter.
type Limiter struct {
	rdb *redislib.Client
}

// New builds a Limiter over an existing Redis client.
func New(rdb *redislib.Client) *Limiter { return &Limiter{rdb: rdb} }

// Allow reports whether one more attempt under key is allowed within the
// last window, given at most max attempts per window. When not allowed,
// retryAfter is how long until the window resets.
func (l *Limiter) Allow(ctx context.Context, key string, max int, window time.Duration) (allowed bool, retryAfter time.Duration, err error) {
	res, err := l.rdb.Eval(ctx, allowScript, []string{key}, int64(window.Seconds())).Result()
	if err != nil {
		return false, 0, fmt.Errorf("ratelimit: eval: %w", err)
	}

	vals, ok := res.([]any)
	if !ok || len(vals) != 2 {
		return false, 0, fmt.Errorf("ratelimit: unexpected script result %#v", res)
	}
	current, ok := vals[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("ratelimit: unexpected count type %#v", vals[0])
	}
	ttl, ok := vals[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("ratelimit: unexpected ttl type %#v", vals[1])
	}

	if current > int64(max) {
		if ttl < 0 {
			ttl = int64(window.Seconds())
		}
		return false, time.Duration(ttl) * time.Second, nil
	}
	return true, 0, nil
}
