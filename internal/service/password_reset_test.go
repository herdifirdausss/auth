package service

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuthService_ForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockSecurityTokenRepository(ctrl)
	eventRepo := mocks.NewMockSecurityEventRepository(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)

	auditService := mocks.NewMockAuditService(ctrl)
	auditService.EXPECT().Log(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)
	s := &AuthServiceImpl{
		userRepo:       userRepo,
		tokenRepo:      tokenRepo,
		eventRepo:      eventRepo,
		membershipRepo: membershipRepo,
		rateLimiter:    rateLimiter,
		auditService:   auditService,
		riskService:      mocks.NewMockRiskService(ctrl),
		pwnedValidator:  mocks.NewMockPwnedValidator(ctrl),
		logger:         slog.Default(),
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
		membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "user-1").Return(nil, nil)
		// eventRepo.Create is no longer called directly on success, it's via auditService (already mocked AnyTimes)

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
		assert.NoError(t, err) // Always no error for anti-enumeration
	})

	t.Run("DatabaseError_UserLookup", func(t *testing.T) {
		rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil)
		userRepo.EXPECT().FindByEmail(gomock.Any(), email).Return(nil, assert.AnError)

		err := s.ForgotPassword(context.Background(), email, ip, ua)
		assert.Error(t, err) // DB errors should be returned
	})
}

func TestAuthService_ResetPassword(t *testing.T) {
	rawToken := "valid-token"
	tokenHash := security.HashToken(rawToken)
	newPassword := "NewSecurePassword123!"

	t.Run("Success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockDB := mocks.NewMockPool(ctrl)
		mockTx := mocks.NewMockTx(ctrl)

		tokenRepo := mocks.NewMockSecurityTokenRepository(ctrl)
		credRepo := mocks.NewMockCredentialRepository(ctrl)
		historyRepo := mocks.NewMockPasswordHistoryRepository(ctrl)
		sessionRepo := mocks.NewMockSessionRepository(ctrl)
		eventRepo := mocks.NewMockSecurityEventRepository(ctrl)
		hasher := mocks.NewMockPasswordHasher(ctrl)

		auditService := mocks.NewMockAuditService(ctrl)
		auditService.EXPECT().Log(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		userRepo := mocks.NewMockUserRepository(ctrl)
		membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)
		riskService := mocks.NewMockRiskService(ctrl)
		pwnedValidator := mocks.NewMockPwnedValidator(ctrl)
		
		pwnedValidator.EXPECT().IsPwned(gomock.Any(), newPassword).Return(false, 0, nil).AnyTimes()

		s := &AuthServiceImpl{
			db:                  mockDB,
			userRepo:            userRepo,
			tokenRepo:           tokenRepo,
			credRepo:            credRepo,
			membershipRepo:      membershipRepo,
			passwordHistoryRepo: historyRepo,
			sessionRepo:         sessionRepo,
			eventRepo:           eventRepo,
			auditService:        auditService,
			hasher:              hasher,
			riskService:         riskService,
			pwnedValidator:      pwnedValidator,
			logger:              slog.Default(),
		}

		token := &model.SecurityToken{
			ID:     "token-1",
			UserID: "user-1",
		}

		tokenRepo.EXPECT().FindValidToken(gomock.Any(), tokenHash, "password_reset").Return(token, nil)
		historyRepo.EXPECT().GetRecentPasswords(gomock.Any(), "user-1", 5).Return([]*model.UserPasswordHistory{{PasswordHash: "old-hash-1", PasswordSalt: "old-salt-1"}}, nil)
		hasher.EXPECT().Verify(newPassword, "old-hash-1", "old-salt-1").Return(false, nil)
		hasher.EXPECT().Hash(newPassword).Return("new-hash", "new-salt", nil)

		mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
		credRepo.EXPECT().UpdatePassword(gomock.Any(), mockTx, "user-1", "new-hash", "new-salt").Return(nil)
		userRepo.EXPECT().UpdatePasswordChangedAt(gomock.Any(), mockTx, "user-1").Return(nil)
		historyRepo.EXPECT().Create(gomock.Any(), mockTx, "user-1", "new-hash", "new-salt").Return(nil)
		historyRepo.EXPECT().Cleanup(gomock.Any(), "user-1", 5).Return(nil)
		tokenRepo.EXPECT().MarkUsed(gomock.Any(), mockTx, "token-1").Return(nil)
		membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "user-1").Return(nil, nil)
		sessionRepo.EXPECT().RevokeAllByUser(gomock.Any(), mockTx, "user-1", "password_reset").Return(nil)
		mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
		mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()
		// eventRepo.Create is no longer called directly on success

		err := s.ResetPassword(context.Background(), rawToken, newPassword, "127.0.0.1", "ua")
		assert.NoError(t, err)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		auditService := mocks.NewMockAuditService(ctrl) // Add auditService mock
		tokenRepo := mocks.NewMockSecurityTokenRepository(ctrl)
		s := &AuthServiceImpl{tokenRepo: tokenRepo, hasher: mocks.NewMockPasswordHasher(ctrl), 			auditService:   auditService,
			riskService:    mocks.NewMockRiskService(ctrl),
			pwnedValidator: mocks.NewMockPwnedValidator(ctrl),
			logger:         slog.Default(),
		}

		tokenRepo.EXPECT().FindValidToken(gomock.Any(), tokenHash, "password_reset").Return(nil, nil)

		err := s.ResetPassword(context.Background(), rawToken, newPassword, "127.0.0.1", "ua")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or expired")
	})

	t.Run("WeakPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		auditService := mocks.NewMockAuditService(ctrl)
		tokenRepo := mocks.NewMockSecurityTokenRepository(ctrl)
		s := &AuthServiceImpl{tokenRepo: tokenRepo, hasher: mocks.NewMockPasswordHasher(ctrl), 			auditService:   auditService,
			riskService:    mocks.NewMockRiskService(ctrl),
			pwnedValidator: mocks.NewMockPwnedValidator(ctrl),
			logger:         slog.Default(),
		}

		token := &model.SecurityToken{ID: "token-1", UserID: "user-1"}
		tokenRepo.EXPECT().FindValidToken(gomock.Any(), tokenHash, "password_reset").Return(token, nil)

		err := s.ResetPassword(context.Background(), rawToken, "weak", "127.0.0.1", "ua")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "weak password")
	})

	t.Run("RecentlyUsedPassword", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tokenRepo := mocks.NewMockSecurityTokenRepository(ctrl)
		historyRepo := mocks.NewMockPasswordHistoryRepository(ctrl)
		hasher := mocks.NewMockPasswordHasher(ctrl)

		auditService := mocks.NewMockAuditService(ctrl)
		s := &AuthServiceImpl{
			tokenRepo:           tokenRepo,
			passwordHistoryRepo: historyRepo,
			hasher:              hasher,
			auditService:        auditService,
			riskService:         mocks.NewMockRiskService(ctrl),
			pwnedValidator:      mocks.NewMockPwnedValidator(ctrl),
			logger:              slog.Default(),
		}
		// db was missing but ResetPassword might reach it if earlier checks pass.
		// However, RecentlyUsedPassword should fail at hasher.Verify or before.
		// Let's add db just in case.
		s.db = mocks.NewMockPool(ctrl)

		token := &model.SecurityToken{ID: "token-1", UserID: "user-1"}
		tokenRepo.EXPECT().FindValidToken(gomock.Any(), tokenHash, "password_reset").Return(token, nil)
		pwnedValidator := s.pwnedValidator.(*mocks.MockPwnedValidator)
		pwnedValidator.EXPECT().IsPwned(gomock.Any(), newPassword).Return(false, 0, nil).AnyTimes()

		historyRepo.EXPECT().GetRecentPasswords(gomock.Any(), "user-1", 5).Return([]*model.UserPasswordHistory{{PasswordHash: "old-hash", PasswordSalt: "old-salt"}}, nil)
		hasher.EXPECT().Verify(newPassword, "old-hash", "old-salt").Return(true, nil)

		err := s.ResetPassword(context.Background(), rawToken, newPassword, "127.0.0.1", "ua")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "recently used")
	})
}

