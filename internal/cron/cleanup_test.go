package cron

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/repository"
	"go.uber.org/mock/gomock"
)

func TestCleanupManager_RunCleanup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sessRepo := repository.NewMockSessionRepository(ctrl)
	rfRepo := repository.NewMockRefreshTokenRepository(ctrl)
	logger := slog.Default()

	m := NewCleanupManager(sessRepo, rfRepo, 1*time.Hour, logger)

	t.Run("Success", func(t *testing.T) {
		sessRepo.EXPECT().CleanupExpired(gomock.Any()).Return(int64(5), nil)
		rfRepo.EXPECT().CleanupExpired(gomock.Any()).Return(int64(10), nil)

		m.runCleanup(context.Background())
	})
}
