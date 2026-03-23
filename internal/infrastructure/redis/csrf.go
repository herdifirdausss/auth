package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type CSRFManager struct {
	client *redis.Client
	ttl    time.Duration
}

func NewCSRFManager(client *redis.Client, ttl time.Duration) *CSRFManager {
	if ttl == 0 {
		ttl = 1 * time.Hour
	}
	return &CSRFManager{client: client, ttl: ttl}
}

func (c *CSRFManager) Generate(ctx context.Context, sessionID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error generating random bytes for CSRF: %w", err)
	}

	token := hex.EncodeToString(b)
	key := fmt.Sprintf("csrf:%s", sessionID)

	if err := c.client.Set(ctx, key, token, c.ttl).Err(); err != nil {
		return "", fmt.Errorf("error saving CSRF token to redis: %w", err)
	}

	return token, nil
}

func (c *CSRFManager) Validate(ctx context.Context, sessionID string, token string) (bool, error) {
	key := fmt.Sprintf("csrf:%s", sessionID)
	savedToken, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, fmt.Errorf("error getting CSRF token from redis: %w", err)
	}

	return savedToken == token, nil
}

func (c *CSRFManager) Invalidate(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("csrf:%s", sessionID)
	return c.client.Del(ctx, key).Err()
}
