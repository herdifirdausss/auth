package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type DistributedLock struct {
	client *redis.Client
}

func NewDistributedLock(client *redis.Client) *DistributedLock {
	return &DistributedLock{client: client}
}

func (d *DistributedLock) Acquire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return d.client.SetNX(ctx, key, "1", ttl).Result()
}

func (d *DistributedLock) Release(ctx context.Context, key string) error {
	return d.client.Del(ctx, key).Err()
}
