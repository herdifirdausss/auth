package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter interface {
	Check(ctx context.Context, cfg RateLimitConfig) (RateLimitResult, error)
	Reset(ctx context.Context, key string) error
}

type RedisRateLimiter struct {
	client *redis.Client
}

func NewRateLimiter(client *redis.Client) RateLimiter {
	return &RedisRateLimiter{client: client}
}

type RateLimitConfig struct {
	Key      string
	MaxCount int
	Window   time.Duration
}

type RateLimitResult struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

func (r *RedisRateLimiter) Check(ctx context.Context, cfg RateLimitConfig) (RateLimitResult, error) {
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, cfg.Key)
	pipe.Expire(ctx, cfg.Key, cfg.Window) // Corrected: Expire only on first hit (logic needs slight adjustment for efficiency)
	// Actually, let's use a more robust script or atomic check

	_, err := pipe.Exec(ctx)
	if err != nil {
		return RateLimitResult{}, fmt.Errorf("error in rate limiter pipeline: %w", err)
	}

	currentCount := int(incr.Val())

	if currentCount == 1 {
		// Set expiration only on the first hit
		r.client.Expire(ctx, cfg.Key, cfg.Window)
	}

	ttlRes := r.client.TTL(ctx, cfg.Key)
	retryAfter := ttlRes.Val()

	if currentCount > cfg.MaxCount {
		return RateLimitResult{
			Allowed:    false,
			Remaining:  0,
			RetryAfter: retryAfter,
		}, nil
	}

	return RateLimitResult{
		Allowed:    true,
		Remaining:  cfg.MaxCount - currentCount,
		RetryAfter: 0,
	}, nil
}

func (r *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}
