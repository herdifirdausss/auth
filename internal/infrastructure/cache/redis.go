package cache

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
)

func NewRedisClient(ctx context.Context, host, port string, db int, logger *slog.Logger) (*redis.Client, error) {
	addr := fmt.Sprintf("%s:%s", host, port)
	client := redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   db,
	})

	// Add OpenTelemetry Tracing and Metrics
	if err := redisotel.InstrumentTracing(client); err != nil {
		return nil, fmt.Errorf("failed to instrument redis tracing: %w", err)
	}
	if err := redisotel.InstrumentMetrics(client); err != nil {
		return nil, fmt.Errorf("failed to instrument redis metrics: %w", err)
	}

	// Startup PING and logging
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	opts := client.Options()
	logger.Info("Redis client initialized",
		"addr", addr,
		"db", opts.DB,
		"pool_size", opts.PoolSize,
	)

	return client, nil
}
