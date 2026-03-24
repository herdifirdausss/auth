package database

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	acquiredConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pgxpool_acquired_connections",
		Help: "The number of currently acquired connections in the pool",
	})
	idleConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pgxpool_idle_connections",
		Help: "The number of currently idle connections in the pool",
	})
	totalConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pgxpool_total_connections",
		Help: "The total number of connections in the pool",
	})
)

func NewPostgresPool(ctx context.Context, dsn string, logger *slog.Logger) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Add OpenTelemetry Tracing
	config.ConnConfig.Tracer = otelpgx.NewTracer()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	// Health check and logging
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	stat := pool.Stat()
	logger.InfoContext(ctx, "Postgres pool initialized",
		"host", config.ConnConfig.Host,
		"max_conns", config.MaxConns,
		"min_conns", config.MinConns,
		"total_conns", stat.TotalConns(),
	)

	// Background metrics collection
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := pool.Stat()
				acquiredConns.Set(float64(s.AcquiredConns()))
				idleConns.Set(float64(s.IdleConns()))
				totalConns.Set(float64(s.TotalConns()))
			}
		}
	}()

	return pool, nil
}
