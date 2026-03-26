package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuthService_Logout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sessRepo := mocks.NewMockSessionRepository(ctrl)
	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	eventRepo := mocks.NewMockSecurityEventRepository(ctrl)
	sessionCache := mocks.NewMockSessionCache(ctrl)

	mockDB := mocks.NewMockPool(ctrl)
	s := &AuthServiceImpl{
		db:               mockDB,
		sessionRepo:      sessRepo,
		refreshTokenRepo: rfRepo,
		eventRepo:        eventRepo,
		sessionCache:     sessionCache,
		riskService:      mocks.NewMockRiskService(ctrl),
		pwnedValidator:   mocks.NewMockPwnedValidator(ctrl),
		logger:           slog.Default(),
	}

	userID := "user-1"
	sessID := "sess-1"
	tokenHash := "hash-1"

	t.Run("Success", func(t *testing.T) {
		mockTx := mocks.NewMockTx(ctrl)
		mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
		sessRepo.EXPECT().RevokeByID(gomock.Any(), sessID, "logout", userID).Return(nil)
		rfRepo.EXPECT().RevokeBySessionID(gomock.Any(), mockTx, sessID).Return(nil)
		mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
		mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

		sessionCache.EXPECT().Delete(gomock.Any(), userID, sessID).Return(nil)

		err := s.Logout(context.Background(), sessID, userID, tokenHash)
		assert.NoError(t, err)
	})
}

func TestAuthService_LogoutAll(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sessRepo := mocks.NewMockSessionRepository(ctrl)
	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	eventRepo := mocks.NewMockSecurityEventRepository(ctrl)
	sessionCache := mocks.NewMockSessionCache(ctrl)

	mockDB := mocks.NewMockPool(ctrl)
	s := &AuthServiceImpl{
		db:               mockDB,
		sessionRepo:      sessRepo,
		refreshTokenRepo: rfRepo,
		eventRepo:        eventRepo,
		sessionCache:     sessionCache,
		logger:           slog.Default(),
	}

	userID := "user-1"

	t.Run("Success", func(t *testing.T) {
		mockTx := mocks.NewMockTx(ctrl)
		mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
		sessRepo.EXPECT().RevokeAllByUser(gomock.Any(), mockTx, userID, "logout_all").Return(nil)
		rfRepo.EXPECT().RevokeAllByUser(gomock.Any(), mockTx, userID).Return(nil)
		mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
		mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

		sessionCache.EXPECT().DeleteByUserID(gomock.Any(), userID).Return(nil)

		err := s.LogoutAll(context.Background(), userID)
		assert.NoError(t, err)
	})
}
