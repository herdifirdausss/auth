package service

import (
	"context"
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

	s := &AuthServiceImpl{
		sessionRepo:      sessRepo,
		refreshTokenRepo: rfRepo,
		eventRepo:        eventRepo,
		sessionCache:     sessionCache,
	}

	userID := "user-1"
	sessID := "sess-1"
	tokenHash := "hash-1"

	t.Run("Success", func(t *testing.T) {
		sessRepo.EXPECT().RevokeByID(gomock.Any(), sessID, "user_logout", userID).Return(nil)
		rfRepo.EXPECT().RevokeBySessionID(gomock.Any(), nil, sessID).Return(nil)
		sessionCache.EXPECT().Delete(gomock.Any(), tokenHash).Return(nil)
		eventRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

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

	s := &AuthServiceImpl{
		sessionRepo:      sessRepo,
		refreshTokenRepo: rfRepo,
		eventRepo:        eventRepo,
	}

	userID := "user-1"

	t.Run("Success", func(t *testing.T) {
		sessRepo.EXPECT().RevokeAllByUser(gomock.Any(), nil, userID, "logout_all").Return(nil)
		rfRepo.EXPECT().RevokeAllByUser(gomock.Any(), nil, userID).Return(nil)
		eventRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		err := s.LogoutAll(context.Background(), userID)
		assert.NoError(t, err)
	})
}
