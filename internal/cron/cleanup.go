package cron

import (
	"context"
	"log/slog"
	"time"

	"github.com/herdifirdausss/auth/internal/repository"
)

type CleanupManager struct {
	sessionRepo repository.SessionRepository
	rfRepo      repository.RefreshTokenRepository
	interval    time.Duration
	stopChan    chan struct{}
	logger      *slog.Logger
}

func NewCleanupManager(sessRepo repository.SessionRepository, rfRepo repository.RefreshTokenRepository, interval time.Duration, l *slog.Logger) *CleanupManager {
	if interval == 0 {
		interval = 1 * time.Hour
	}
	return &CleanupManager{
		sessionRepo: sessRepo,
		rfRepo:      rfRepo,
		interval:    interval,
		stopChan:    make(chan struct{}),
		logger:      l,
	}
}

func (m *CleanupManager) Start(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	m.logger.InfoContext(ctx, "Cleanup manager started", "interval", m.interval)

	// Run once at start
	m.runCleanup(ctx)

	for {
		select {
		case <-ticker.C:
			m.runCleanup(ctx)
		case <-m.stopChan:
			m.logger.Info("Cleanup manager stopping")
			return
		case <-ctx.Done():
			m.logger.InfoContext(ctx, "Cleanup manager context done, stopping")
			return
		}
	}
}

func (m *CleanupManager) Stop() {
	close(m.stopChan)
}

func (m *CleanupManager) runCleanup(ctx context.Context) {
	start := time.Now()
	m.logger.InfoContext(ctx, "Starting background cleanup")

	sessCount, err := m.sessionRepo.CleanupExpired(ctx)
	if err != nil {
		m.logger.ErrorContext(ctx, "Error cleaning up sessions", "error", err)
	}

	rfCount, err := m.rfRepo.CleanupExpired(ctx)
	if err != nil {
		m.logger.ErrorContext(ctx, "Error cleaning up refresh tokens", "error", err)
	}

	m.logger.InfoContext(ctx, "Cleanup finished", 
		"removed_sessions", sessCount, 
		"removed_refresh_tokens", rfCount, 
		"duration", time.Since(start))
}
