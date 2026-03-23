package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=redis
type SessionCache interface {
	Set(ctx context.Context, tokenHash string, session *CachedSession) error
	Get(ctx context.Context, tokenHash string) (*CachedSession, error)
	Delete(ctx context.Context, tokenHash string) error
}

type RedisSessionCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewSessionCache(client *redis.Client, ttl time.Duration) SessionCache {
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	return &RedisSessionCache{client: client, ttl: ttl}
}

type CachedSession struct {
	SessionID     string    `json:"session_id"`
	UserID        string    `json:"user_id"`
	TenantID      string    `json:"tenant_id"`
	MFAVerified   bool      `json:"mfa_verified"`
	ExpiresAt     time.Time `json:"expires_at"`
	IdleTimeoutAt time.Time `json:"idle_timeout_at"`
}

func (s *RedisSessionCache) Set(ctx context.Context, tokenHash string, session *CachedSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("error marshaling session: %w", err)
	}

	key := fmt.Sprintf("session:cache:%s", tokenHash)
	return s.client.Set(ctx, key, data, s.ttl).Err()
}

func (s *RedisSessionCache) Get(ctx context.Context, tokenHash string) (*CachedSession, error) {
	key := fmt.Sprintf("session:cache:%s", tokenHash)
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, fmt.Errorf("error getting session from cache: %w", err)
	}

	var session CachedSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("error unmarshaling session: %w", err)
	}

	return &session, nil
}

func (s *RedisSessionCache) Delete(ctx context.Context, tokenHash string) error {
	key := fmt.Sprintf("session:cache:%s", tokenHash)
	return s.client.Del(ctx, key).Err()
}
