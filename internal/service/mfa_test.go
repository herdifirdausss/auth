package service

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/xlzd/gotp"
	"go.uber.org/mock/gomock"
)

func TestMFAService_SetupTOTP(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfaRepo := mocks.NewMockMFARepository(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey: []byte("test-secret"),
		Issuer:    "test",
	}

	svc := NewMFAService(nil, mfaRepo, nil, nil, nil, jwtConfig, rateLimiter, slog.Default())

	mfaRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

	res, err := svc.SetupTOTP(context.Background(), "user-1", "user@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QRCodeURL)
}

func TestMFAService_VerifySetup(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfaRepo := mocks.NewMockMFARepository(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey: []byte("test-secret"),
		Issuer:    "test",
	}

	svc := NewMFAService(nil, mfaRepo, nil, nil, nil, jwtConfig, rateLimiter, slog.Default())

	encryptionKey := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
	secret := "JBSWY3DPEHPK3PXP" // base32
	encryptedSecret, _ := security.Encrypt(secret, encryptionKey)

	method := &model.MFAMethod{
		ID:              "mfa-1",
		UserID:          "user-1",
		SecretEncrypted: encryptedSecret,
	}

	totp := gotp.NewDefaultTOTP(secret)
	otpCode := totp.Now()

	rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, cfg redis.RateLimitConfig) (redis.RateLimitResult, error) {
		if cfg.Key != "mfa_setup:user-1" {
			return redis.RateLimitResult{Allowed: false}, nil
		}
		return redis.RateLimitResult{Allowed: true}, nil
	})
	mfaRepo.EXPECT().FindInactiveByUser(gomock.Any(), "user-1", "totp").Return(method, nil)
	mfaRepo.EXPECT().Activate(gomock.Any(), "mfa-1").Return(nil)
	mfaRepo.EXPECT().SetBackupCodes(gomock.Any(), "mfa-1", gomock.Any()).Return(nil)

	res, err := svc.VerifySetup(context.Background(), "user-1", otpCode)
	assert.NoError(t, err)
	assert.Len(t, res.BackupCodes, 10)
}

func TestMFAService_Challenge(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfaRepo := mocks.NewMockMFARepository(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)
	mockDB := mocks.NewMockTransactor(ctrl)
	mockTx := mocks.NewMockTx(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("test-secret-key-32-chars-long-!!!"),
		Issuer:       "test",
		AccessExpiry: 15 * time.Minute,
	}

	svc := NewMFAService(mockDB, mfaRepo, nil, sessRepo, rfRepo, jwtConfig, rateLimiter, slog.Default())

	userID := "user-1"
	mfaToken, _ := security.GenerateMFAToken(jwtConfig, userID, 5*time.Minute)

	encryptionKey := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
	secret := "JBSWY3DPEHPK3PXP"
	encryptedSecret, _ := security.Encrypt(secret, encryptionKey)

	method := &model.MFAMethod{
		ID:              "mfa-1",
		UserID:          userID,
		SecretEncrypted: encryptedSecret,
	}

	totp := gotp.NewDefaultTOTP(secret)
	otpCode := totp.Now()

	rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, cfg redis.RateLimitConfig) (redis.RateLimitResult, error) {
		if cfg.Key != "mfa_challenge:"+userID {
			return redis.RateLimitResult{Allowed: false}, nil
		}
		return redis.RateLimitResult{Allowed: true}, nil
	})
	mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), userID).Return(method, nil)

	mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
	sessRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil)
	rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil)
	mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
	mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	res, err := svc.Challenge(context.Background(), mfaToken, otpCode, "127.0.0.1", "ua", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
}

