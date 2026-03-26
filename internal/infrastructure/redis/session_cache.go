package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOFILE -package=mocks
type SessionCache interface {
	Set(ctx context.Context, tokenHash string, session *CachedSession) error
	Get(ctx context.Context, tokenHash string) (*CachedSession, error)
	Delete(ctx context.Context, userID, tokenHash string) error
	DeleteByUserID(ctx context.Context, userID string) error
	SetRaw(ctx context.Context, key string, data string, ttl time.Duration) error
	GetRaw(ctx context.Context, key string) (string, error)
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
	SessionID         string    `json:"session_id"`
	UserID            string    `json:"user_id"`
	TenantID          string    `json:"tenant_id"`
	TokenHash         string    `json:"token_hash"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	MFAVerified       bool      `json:"mfa_verified"`
	ExpiresAt         time.Time `json:"expires_at"`
	IdleTimeoutAt     time.Time `json:"idle_timeout_at"`
}

func (s *RedisSessionCache) Set(ctx context.Context, tokenHash string, session *CachedSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("error marshaling session: %w", err)
	}

	pipe := s.client.Pipeline()
	
	sessionKey := fmt.Sprintf("session:cache:%s", tokenHash)
	pipe.Set(ctx, sessionKey, data, s.ttl)
	
	userKey := fmt.Sprintf("user:sessions:%s", session.UserID)
	pipe.SAdd(ctx, userKey, tokenHash)
	// Refresh user key TTL to match session TTL (approximate)
	pipe.Expire(ctx, userKey, 30*24*time.Hour) 

	_, err = pipe.Exec(ctx)
	return err
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

func (s *RedisSessionCache) Delete(ctx context.Context, userID, tokenHash string) error {
	pipe := s.client.Pipeline()
	
	sessionKey := fmt.Sprintf("session:cache:%s", tokenHash)
	pipe.Del(ctx, sessionKey)
	
	userKey := fmt.Sprintf("user:sessions:%s", userID)
	pipe.SRem(ctx, userKey, tokenHash)
	
	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisSessionCache) DeleteByUserID(ctx context.Context, userID string) error {
	userKey := fmt.Sprintf("user:sessions:%s", userID)
	
	// Get all cached tokens for this user
	tokenHashes, err := s.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return fmt.Errorf("error getting user sessions from redis: %w", err)
	}
	
	if len(tokenHashes) == 0 {
		return nil
	}

	pipe := s.client.Pipeline()
	for _, hash := range tokenHashes {
		pipe.Del(ctx, fmt.Sprintf("session:cache:%s", hash))
	}
	pipe.Del(ctx, userKey)
	
	_, err = pipe.Exec(ctx)
	return err
}
func (s *RedisSessionCache) SetRaw(ctx context.Context, key string, data string, ttl time.Duration) error {
	return s.client.Set(ctx, key, data, ttl).Err()
}

func (s *RedisSessionCache) GetRaw(ctx context.Context, key string) (string, error) {
	return s.client.Get(ctx, key).Result()
}
