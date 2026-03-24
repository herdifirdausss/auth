package service

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/text/unicode/norm"
)

func TestRegister_UnicodeNormalization(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mocks.NewMockUserRepository(ctrl)
	s := &AuthServiceImpl{
		userRepo: userRepo,
		logger:   slog.Default(),
	}

	// Case 1: user@exämple.com (NFC)
	emailNFC := "user@exämple.com"
	// Case 2: user@exämple.com (NFD)
	emailNFD := norm.NFD.String(emailNFC)

	assert.NotEqual(t, emailNFC, emailNFD, "NFC and NFD should be different strings")

	ctx := context.Background()
	req := &model.RegisterRequest{
		Email:    emailNFD,
		Username: "testuser",
		Password:   "Password123!",
		TenantSlug: "test-tenant",
	}

	// Expect ExistsByEmail to be called with normalized NFC email
	normalizedEmail := "user@exämple.com" // NFC
	userRepo.EXPECT().ExistsByEmail(ctx, normalizedEmail).Return(true, nil)

	_, err := s.Register(ctx, req, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email already exists")
}

func TestLogin_TimingAttackDummyHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mocks.NewMockUserRepository(ctrl)
	hasher := mocks.NewMockPasswordHasher(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)
	
	s := &AuthServiceImpl{
		userRepo:    userRepo,
		hasher:      hasher,
		rateLimiter: rateLimiter,
		logger:      slog.Default(),
	}

	ctx := context.Background()
	req := &model.LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "Password123!",
	}

	// 1. Rate limiter allowed
	rateLimiter.EXPECT().Check(ctx, gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).Times(2)
	
	// 2. User not found
	userRepo.EXPECT().FindByEmail(ctx, req.Email).Return(nil, nil)

	// 3. EXPECT dummy hash verify to be called!
	// dummyHash := "0000000000000000000000000000000000000000000000000000000000000000"
	// dummySalt := "00000000000000000000000000000000"
	hasher.EXPECT().Verify(req.Password, gomock.Any(), gomock.Any()).Return(false, nil)

	_, err := s.Login(ctx, req, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Equal(t, "invalid email or password", err.Error())
}

func TestRegister_NullByteInjection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := mocks.NewMockUserRepository(ctrl)
	hasher := mocks.NewMockPasswordHasher(ctrl)
	
	s := &AuthServiceImpl{
		userRepo: userRepo,
		hasher:   hasher,
		logger:   slog.Default(),
	}

	ctx := context.Background()
	passwordWithNull := "Password123!\x00malicious"
	req := &model.RegisterRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password:   passwordWithNull,
		TenantSlug: "test-tenant",
	}

	// Expect hasher.Hash to be called with the full password (including null byte)
	hasher.EXPECT().Hash(passwordWithNull).Return("hash", "salt", nil)
	userRepo.EXPECT().ExistsByEmail(gomock.Any(), gomock.Any()).Return(false, nil)
	userRepo.EXPECT().ExistsByUsername(gomock.Any(), gomock.Any()).Return(false, nil)
	
	// Just test that the full password reaches the hasher
	// (Transaction setup omitted for brevity in this specific unit test, or just mock everything)
	
	// For this test, I'll just check if it reaches Hash.
	// Actually, I need a complete mock setup or it will panic.
	// I'll skip the rest of Register if I just want to test if Hash is called.
	
	// Let's mock DB Begin to fail to stop early.
	db := mocks.NewMockTransactor(ctrl)
	s.db = db
	db.EXPECT().Begin(ctx).Return(nil, fmt.Errorf("stop test here"))

	_, _ = s.Register(ctx, req, "1.1.1.1", "ua")
}
