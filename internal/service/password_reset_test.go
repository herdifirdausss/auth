package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuthService_ForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := repository.NewMockUserRepository(ctrl)
	tokenRepo := repository.NewMockSecurityTokenRepository(ctrl)
	eventRepo := repository.NewMockSecurityEventRepository(ctrl)
	rateLimiter := redis.NewMockRateLimiter(ctrl)

	s := &AuthServiceImpl{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		eventRepo:   eventRepo,
		rateLimiter: rateLimiter,
	}

	email := "test@example.com"
	ip := "127.0.0.1"
	ua := "test-agent"

	t.Run("Success", func(t *testing.T) {
		user := &model.User{ID: "user-1", Email: email}
		
		rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, cfg redis.RateLimitConfig) (redis.RateLimitResult, error) {
			if cfg.Key != fmt.Sprintf("password_reset_lock:%s", email) {
				return redis.RateLimitResult{Allowed: false}, fmt.Errorf("wrong key")
			}
			return redis.RateLimitResult{Allowed: true}, nil
		})
		
		userRepo.EXPECT().FindByEmail(gomock.Any(), email).Return(user, nil)
		tokenRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
		eventRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		err := s.ForgotPassword(context.Background(), email, ip, ua)
		assert.NoError(t, err)
	})

	t.Run("RateLimited", func(t *testing.T) {
		rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: false}, nil)

		err := s.ForgotPassword(context.Background(), email, ip, ua)
		assert.NoError(t, err) // Should still be no error for anti-enumeration
	})

	t.Run("UserNotFound", func(t *testing.T) {
		rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil)
		userRepo.EXPECT().FindByEmail(gomock.Any(), email).Return(nil, nil)

		err := s.ForgotPassword(context.Background(), email, ip, ua)
		assert.NoError(t, err) // Should still be no error for anti-enumeration
	})
}

func TestAuthService_ResetPassword(t *testing.T) {
	rawToken := "valid-token"
	tokenHash := security.HashToken(rawToken)
	newPassword := "NewSecurePassword123!"

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		db, sqlMock, _ := sqlmock.New()
		defer db.Close()

		tokenRepo := repository.NewMockSecurityTokenRepository(ctrl)
		credRepo := repository.NewMockCredentialRepository(ctrl)
		historyRepo := repository.NewMockPasswordHistoryRepository(ctrl)
		sessionRepo := repository.NewMockSessionRepository(ctrl)
		eventRepo := repository.NewMockSecurityEventRepository(ctrl)
		hasher := security.NewMockPasswordHasher(ctrl)

		s := &AuthServiceImpl{
			db:                  db,
			tokenRepo:           tokenRepo,
			credRepo:            credRepo,
			passwordHistoryRepo: historyRepo,
			sessionRepo:         sessionRepo,
			eventRepo:           eventRepo,
			hasher:              hasher,
		}

		token := &model.SecurityToken{
			ID:     "token-1",
			UserID: "user-1",
		}

		tokenRepo.EXPECT().FindValidToken(gomock.Any(), tokenHash, "password_reset").Return(token, nil)
		historyRepo.EXPECT().GetRecentPasswords(gomock.Any(), "user-1", 5).Return([]string{"old-hash-1"}, nil)
		hasher.EXPECT().Verify(newPassword, "old-hash-1", "").Return(false, nil)
		hasher.EXPECT().Hash(newPassword).Return("new-hash", "new-salt", nil)

		sqlMock.ExpectBegin()
		credRepo.EXPECT().UpdatePassword(gomock.Any(), gomock.Any(), "user-1", "new-hash", "new-salt").Return(nil)
		historyRepo.EXPECT().Create(gomock.Any(), gomock.Any(), "user-1", "new-hash").Return(nil)
		historyRepo.EXPECT().Cleanup(gomock.Any(), "user-1", 5).Return(nil)
		tokenRepo.EXPECT().MarkUsed(gomock.Any(), gomock.Any(), "token-1").Return(nil)
		sessionRepo.EXPECT().RevokeAllByUser(gomock.Any(), gomock.Any(), "user-1", "password_reset").Return(nil)
		sqlMock.ExpectCommit()
		eventRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

		err := s.ResetPassword(context.Background(), rawToken, newPassword, "127.0.0.1", "ua")
		assert.NoError(t, err)
		assert.NoError(t, sqlMock.ExpectationsWereMet())
	})

	t.Run("RecentlyUsedPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		db, _, _ := sqlmock.New()
		defer db.Close()

		tokenRepo := repository.NewMockSecurityTokenRepository(ctrl)
		historyRepo := repository.NewMockPasswordHistoryRepository(ctrl)
		hasher := security.NewMockPasswordHasher(ctrl)

		s := &AuthServiceImpl{
			db:                  db,
			tokenRepo:           tokenRepo,
			passwordHistoryRepo: historyRepo,
			hasher:              hasher,
		}

		token := &model.SecurityToken{ID: "token-1", UserID: "user-1"}
		tokenRepo.EXPECT().FindValidToken(gomock.Any(), tokenHash, "password_reset").Return(token, nil)
		historyRepo.EXPECT().GetRecentPasswords(gomock.Any(), "user-1", 5).Return([]string{"old-hash"}, nil)
		hasher.EXPECT().Verify(newPassword, "old-hash", "").Return(true, nil)

		err := s.ResetPassword(context.Background(), rawToken, newPassword, "127.0.0.1", "ua")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "recently used")
	})
}
