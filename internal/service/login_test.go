package service

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func setupLoginTest(t *testing.T) (*AuthServiceImpl, *mocks.MockUserRepository, *mocks.MockCredentialRepository, *mocks.MockPasswordHasher, *mocks.MockRateLimiter, *mocks.MockSecurityEventRepository, *mocks.MockTransactor, *mocks.MockSessionRepository, *mocks.MockRefreshTokenRepository, *mocks.MockMFARepository, *mocks.MockSessionCache, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	
	userRepo := mocks.NewMockUserRepository(ctrl)
	credRepo := mocks.NewMockCredentialRepository(ctrl)
	hasher := mocks.NewMockPasswordHasher(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)
	eventRepo := mocks.NewMockSecurityEventRepository(ctrl)
	db := mocks.NewMockTransactor(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	mfaRepo := mocks.NewMockMFARepository(ctrl)
	sessionCache := mocks.NewMockSessionCache(ctrl)

	s := &AuthServiceImpl{
		db:                  db,
		userRepo:            userRepo,
		credRepo:            credRepo,
		hasher:              hasher,
		rateLimiter:         rateLimiter,
		eventRepo:           eventRepo,
		sessionRepo:         sessRepo,
		refreshTokenRepo:    rfRepo,
		mfaRepo:             mfaRepo,
		sessionCache:        sessionCache,
		membershipRepo:      mocks.NewMockTenantMembershipRepository(ctrl),
		jwtConfig: security.JWTConfig{
			SecretKey:    []byte("test-secret-key-at-least-thirty-two-bytes-long"),
			AccessExpiry: 15 * time.Minute,
		},
		logger: slog.Default(),
	}

	return s, userRepo, credRepo, hasher, rateLimiter, eventRepo, db, sessRepo, rfRepo, mfaRepo, sessionCache, ctrl
}

func TestLogin_Success(t *testing.T) {
	s, userRepo, credRepo, hasher, rateLimiter, eventRepo, db, sessRepo, rfRepo, mfaRepo, sessionCache, ctrl := setupLoginTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	req := &model.LoginRequest{
		Email:    "test@example.com",
		Password: "Password123!",
	}
	ip := "1.1.1.1"
	ua := "ua"

	user := &model.User{ID: "user-1", Email: req.Email, IsActive: true, IsVerified: true}
	cred := &model.UserCredential{UserID: user.ID, PasswordHash: "hash", PasswordSalt: "salt"}

	rateLimiter.EXPECT().Check(ctx, gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).Times(2)
	userRepo.EXPECT().FindByEmail(ctx, req.Email).Return(user, nil)
	credRepo.EXPECT().FindByUserID(ctx, user.ID).Return(cred, nil)
	hasher.EXPECT().Verify(req.Password, cred.PasswordHash, cred.PasswordSalt).Return(true, nil)
	userRepo.EXPECT().ResetFailedLoginAndUpdateLastLogin(ctx, user.ID, ip).Return(nil)
	
	// Mock MembershipRepo (added to setupLoginTest helper properly if needed, but here I'll just use it)
	membershipRepo := s.membershipRepo.(*mocks.MockTenantMembershipRepository)
	membershipRepo.EXPECT().FindActiveByUserID(ctx, user.ID).Return(nil, nil)
	mfaRepo.EXPECT().FindPrimaryActive(ctx, user.ID).Return(nil, nil)
	mockTx := mocks.NewMockTx(ctrl)
	db.EXPECT().Begin(ctx).Return(mockTx, nil)
	sessRepo.EXPECT().Create(ctx, mockTx, gomock.Any()).Return(nil)
	rfRepo.EXPECT().Create(ctx, mockTx, gomock.Any()).Return(nil)
	mockTx.EXPECT().Commit(ctx).Return(nil)
	mockTx.EXPECT().Rollback(ctx).Return(nil).AnyTimes()

	sessionCache.EXPECT().Set(ctx, gomock.Any(), gomock.Any()).Return(nil)
	eventRepo.EXPECT().Create(ctx, gomock.Any()).Return(nil)

	res, err := s.Login(ctx, req, ip, ua)
	
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
}

func TestLogin_UserNotFound_DummyHash(t *testing.T) {
	s, userRepo, _, hasher, rateLimiter, _, _, _, _, _, _, ctrl := setupLoginTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	req := &model.LoginRequest{Email: "notfound@example.com", Password: "any"}
	
	rateLimiter.EXPECT().Check(ctx, gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).Times(2)
	userRepo.EXPECT().FindByEmail(gomock.Any(), gomock.Any()).Return(nil, nil)
	hasher.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)

	_, err := s.Login(ctx, req, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Equal(t, "invalid email or password", err.Error())
}

func TestLogin_WrongPassword_Suspension(t *testing.T) {
	s, userRepo, credRepo, hasher, rateLimiter, eventRepo, _, _, _, _, _, ctrl := setupLoginTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	req := &model.LoginRequest{Email: "test@example.com", Password: "wrong"}
	user := &model.User{ID: "user-1", Email: "test@example.com", IsVerified: true}
	cred := &model.UserCredential{UserID: "user-1", PasswordHash: "h", PasswordSalt: "s"}

	rateLimiter.EXPECT().Check(ctx, gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).Times(2)
	userRepo.EXPECT().FindByEmail(ctx, "test@example.com").Return(user, nil)
	credRepo.EXPECT().FindByUserID(ctx, user.ID).Return(cred, nil)
	hasher.EXPECT().Verify(req.Password, cred.PasswordHash, cred.PasswordSalt).Return(false, nil)
	
	// Increment failed login and check if it reaches 10
	userRepo.EXPECT().IncrementFailedLogin(ctx, user.ID).Return(10, nil)
	userRepo.EXPECT().SuspendUser(ctx, user.ID).Return(nil)
	eventRepo.EXPECT().Create(ctx, gomock.Any()).Return(nil)

	_, err := s.Login(ctx, req, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Equal(t, "invalid email or password", err.Error())
}

func TestLogin_PartialFailure_DBTimeout(t *testing.T) {
	s, userRepo, _, _, rateLimiter, _, _, _, _, _, _, ctrl := setupLoginTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	req := &model.LoginRequest{Email: "test@example.com", Password: "any"}
	
	rateLimiter.EXPECT().Check(ctx, gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).Times(2)
	userRepo.EXPECT().FindByEmail(ctx, "test@example.com").Return(nil, fmt.Errorf("DB timeout"))

	_, err := s.Login(ctx, req, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Equal(t, "DB timeout", err.Error())
}

func TestLogin_AccountSuspended(t *testing.T) {
	s, userRepo, _, _, rateLimiter, _, _, _, _, _, _, ctrl := setupLoginTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	req := &model.LoginRequest{Email: "suspended@example.com", Password: "any"}
	user := &model.User{ID: "user-1", Email: req.Email, IsSuspended: true}
	
	rateLimiter.EXPECT().Check(ctx, gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).Times(2)
	userRepo.EXPECT().FindByEmail(ctx, req.Email).Return(user, nil)

	_, err := s.Login(ctx, req, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Equal(t, "account has been suspended", err.Error())
}
