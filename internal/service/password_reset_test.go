package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthService_ForgotPassword(t *testing.T) {
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockSecurityTokenRepo)
	eventRepo := new(mockSecurityEventRepo)
	rateLimiter := new(mockRateLimiter)

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
		
		rateLimiter.On("Check", mock.Anything, mock.MatchedBy(func(cfg redis.RateLimitConfig) bool {
			return cfg.Key == fmt.Sprintf("password_reset_lock:%s", email)
		})).Return(redis.RateLimitResult{Allowed: true}, nil)
		
		userRepo.On("FindByEmail", mock.Anything, email).Return(user, nil)
		tokenRepo.On("Create", mock.Anything, mock.Anything).Return(nil)
		eventRepo.On("Create", mock.Anything).Return(nil)

		err := s.ForgotPassword(context.Background(), email, ip, ua)
		assert.NoError(t, err)
		rateLimiter.AssertExpectations(t)
		userRepo.AssertExpectations(t)
		tokenRepo.AssertExpectations(t)
	})

	t.Run("RateLimited", func(t *testing.T) {
		rateLimiter.On("Check", mock.Anything, mock.Anything).Return(redis.RateLimitResult{Allowed: false}, nil)

		err := s.ForgotPassword(context.Background(), email, ip, ua)
		assert.NoError(t, err) // Should still be no error for anti-enumeration
	})

	t.Run("UserNotFound", func(t *testing.T) {
		rateLimiter.On("Check", mock.Anything, mock.Anything).Return(redis.RateLimitResult{Allowed: true}, nil)
		userRepo.On("FindByEmail", mock.Anything, email).Return(nil, nil)

		err := s.ForgotPassword(context.Background(), email, ip, ua)
		assert.NoError(t, err) // Should still be no error for anti-enumeration
	})
}

func TestAuthService_ResetPassword(t *testing.T) {
	rawToken := "valid-token"
	tokenHash := security.HashToken(rawToken)
	newPassword := "NewSecurePassword123!"

	t.Run("Success", func(t *testing.T) {
		db, sqlMock, _ := sqlmock.New()
		defer db.Close()

		tokenRepo := new(mockSecurityTokenRepo)
		credRepo := new(mockCredentialRepo)
		historyRepo := new(mockPasswordHistoryRepo)
		sessionRepo := new(mockSessionRepo)
		eventRepo := new(mockSecurityEventRepo)
		hasher := new(mockPasswordHasher)

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

		tokenRepo.On("FindValidToken", mock.Anything, tokenHash, "password_reset").Return(token, nil)
		historyRepo.On("GetRecentPasswords", mock.Anything, "user-1", 5).Return([]string{"old-hash-1"}, nil)
		hasher.On("Verify", newPassword, "old-hash-1", "").Return(false, nil)
		hasher.On("Hash", newPassword).Return("new-hash", "new-salt", nil)

		sqlMock.ExpectBegin()
		credRepo.On("UpdatePassword", mock.Anything, mock.Anything, "user-1", "new-hash", "new-salt").Return(nil)
		historyRepo.On("Create", mock.Anything, mock.Anything, "user-1", "new-hash").Return(nil)
		historyRepo.On("Cleanup", mock.Anything, "user-1", 5).Return(nil)
		tokenRepo.On("MarkUsed", mock.Anything, mock.Anything, "token-1").Return(nil)
		sessionRepo.On("RevokeAllByUser", mock.Anything, mock.Anything, "user-1", "password_reset").Return(nil)
		sqlMock.ExpectCommit()
		eventRepo.On("Create", mock.Anything).Return(nil)

		err := s.ResetPassword(context.Background(), rawToken, newPassword, "127.0.0.1", "ua")
		assert.NoError(t, err)
		assert.NoError(t, sqlMock.ExpectationsWereMet())
	})

	t.Run("RecentlyUsedPassword", func(t *testing.T) {
		db, _, _ := sqlmock.New()
		defer db.Close()

		tokenRepo := new(mockSecurityTokenRepo)
		historyRepo := new(mockPasswordHistoryRepo)
		hasher := new(mockPasswordHasher)

		s := &AuthServiceImpl{
			db:                  db,
			tokenRepo:           tokenRepo,
			passwordHistoryRepo: historyRepo,
			hasher:              hasher,
		}

		token := &model.SecurityToken{ID: "token-1", UserID: "user-1"}
		tokenRepo.On("FindValidToken", mock.Anything, tokenHash, "password_reset").Return(token, nil)
		historyRepo.On("GetRecentPasswords", mock.Anything, "user-1", 5).Return([]string{"old-hash"}, nil)
		hasher.On("Verify", newPassword, "old-hash", "").Return(true, nil)

		err := s.ResetPassword(context.Background(), rawToken, newPassword, "127.0.0.1", "ua")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "recently used")
	})
}
