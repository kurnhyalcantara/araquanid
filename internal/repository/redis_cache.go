package repository

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

// redisCache is a read-through cache decorator around another Repository.
// It demonstrates composing outbound adapters: the usecase still sees a
// single Repository.
type redisCache struct {
	next   Repository
	client *redis.Client
	ttl    time.Duration
	log    *slog.Logger
}

// NewRedisCache wraps `next` with read-through caching of GetByID lookups.
// Cache failures are logged and degrade to the underlying repository; they
// never fail the request.
func NewRedisCache(next Repository, client *redis.Client, ttl time.Duration, log *slog.Logger) Repository {
	return &redisCache{next: next, client: client, ttl: ttl, log: log}
}

func cacheKey(id string) string { return "example:" + id }

func (c *redisCache) Create(ctx context.Context, e *domain.Example) error {
	if err := c.next.Create(ctx, e); err != nil {
		return err
	}
	c.set(ctx, e)
	return nil
}

func (c *redisCache) GetByID(ctx context.Context, id string) (*domain.Example, error) {
	if data, err := c.client.Get(ctx, cacheKey(id)).Bytes(); err == nil {
		var e domain.Example
		if err := json.Unmarshal(data, &e); err == nil {
			return &e, nil
		}
	} else if err != redis.Nil {
		c.log.WarnContext(ctx, "example cache read failed", slog.String("error", err.Error()))
	}

	e, err := c.next.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	c.set(ctx, e)
	return e, nil
}

// List always hits the primary store: list results are not cached.
func (c *redisCache) List(ctx context.Context, limit, offset int) ([]*domain.Example, int64, error) {
	return c.next.List(ctx, limit, offset)
}

func (c *redisCache) Update(ctx context.Context, e *domain.Example) error {
	if err := c.next.Update(ctx, e); err != nil {
		return err
	}
	c.invalidate(ctx, e.ID)
	return nil
}

func (c *redisCache) Delete(ctx context.Context, id string) error {
	if err := c.next.Delete(ctx, id); err != nil {
		return err
	}
	c.invalidate(ctx, id)
	return nil
}

func (c *redisCache) set(ctx context.Context, e *domain.Example) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	if err := c.client.Set(ctx, cacheKey(e.ID), data, c.ttl).Err(); err != nil {
		c.log.WarnContext(ctx, "example cache write failed", slog.String("error", err.Error()))
	}
}

func (c *redisCache) invalidate(ctx context.Context, id string) {
	if err := c.client.Del(ctx, cacheKey(id)).Err(); err != nil {
		c.log.WarnContext(ctx, "example cache invalidation failed",
			slog.String("example_id", id), slog.String("error", err.Error()))
	}
}
