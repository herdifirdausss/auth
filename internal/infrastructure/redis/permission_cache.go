package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/redis/go-redis/v9"
)

//go:generate mockgen -source=$GOFILE -destination=../../mocks/mock_$GOFILE -package=mocks
type PermissionCache interface {
	SetPermissions(ctx context.Context, tenantID, userID string, permissions []string) error
	GetPermissions(ctx context.Context, tenantID, userID string) ([]string, error)
	SetRoles(ctx context.Context, tenantID, userID string, roles []model.Role) error
	GetRoles(ctx context.Context, tenantID, userID string) ([]model.Role, error)
	Invalidate(ctx context.Context, tenantID, userID string) error
}

type RedisPermissionCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewPermissionCache(client *redis.Client, ttl time.Duration) PermissionCache {
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	return &RedisPermissionCache{client: client, ttl: ttl}
}

func (c *RedisPermissionCache) SetPermissions(ctx context.Context, tenantID, userID string, permissions []string) error {
	key := fmt.Sprintf("perm:%s:%s:perms", tenantID, userID)
	data, err := json.Marshal(permissions)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, key, data, c.ttl).Err()
}

func (c *RedisPermissionCache) GetPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	key := fmt.Sprintf("perm:%s:%s:perms", tenantID, userID)
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	var permissions []string
	err = json.Unmarshal(data, &permissions)
	return permissions, err
}

func (c *RedisPermissionCache) SetRoles(ctx context.Context, tenantID, userID string, roles []model.Role) error {
	key := fmt.Sprintf("perm:%s:%s:roles", tenantID, userID)
	data, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, key, data, c.ttl).Err()
}

func (c *RedisPermissionCache) GetRoles(ctx context.Context, tenantID, userID string) ([]model.Role, error) {
	key := fmt.Sprintf("perm:%s:%s:roles", tenantID, userID)
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	var roles []model.Role
	err = json.Unmarshal(data, &roles)
	return roles, err
}

func (c *RedisPermissionCache) Invalidate(ctx context.Context, tenantID, userID string) error {
	key1 := fmt.Sprintf("perm:%s:%s:perms", tenantID, userID)
	key2 := fmt.Sprintf("perm:%s:%s:roles", tenantID, userID)
	return c.client.Del(ctx, key1, key2).Err()
}
