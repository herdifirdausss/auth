package cron

import (
	"context"
	"log"
	"time"

	"github.com/herdifirdausss/auth/internal/repository"
)

type CleanupManager struct {
	sessionRepo repository.SessionRepository
	rfRepo      repository.RefreshTokenRepository
	interval    time.Duration
	stopChan    chan struct{}
}

func NewCleanupManager(sessRepo repository.SessionRepository, rfRepo repository.RefreshTokenRepository, interval time.Duration) *CleanupManager {
	if interval == 0 {
		interval = 1 * time.Hour
	}
	return &CleanupManager{
		sessionRepo: sessRepo,
		rfRepo:      rfRepo,
		interval:    interval,
		stopChan:    make(chan struct{}),
	}
}

func (m *CleanupManager) Start(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	log.Printf("Cleanup manager started with interval %v", m.interval)

	// Run once at start
	m.runCleanup(ctx)

	for {
		select {
		case <-ticker.C:
			m.runCleanup(ctx)
		case <-m.stopChan:
			log.Println("Cleanup manager stopping...")
			return
		case <-ctx.Done():
			log.Println("Cleanup manager context done, stopping...")
			return
		}
	}
}

func (m *CleanupManager) Stop() {
	close(m.stopChan)
}

func (m *CleanupManager) runCleanup(ctx context.Context) {
	start := time.Now()
	log.Println("Starting background cleanup...")

	sessCount, err := m.sessionRepo.CleanupExpired(ctx)
	if err != nil {
		log.Printf("Error cleaning up sessions: %v", err)
	}

	rfCount, err := m.rfRepo.CleanupExpired(ctx)
	if err != nil {
		log.Printf("Error cleaning up refresh tokens: %v", err)
	}

	log.Printf("Cleanup finished. Removed %d sessions and %d refresh tokens. Duration: %v", 
		sessCount, rfCount, time.Since(start))
}
