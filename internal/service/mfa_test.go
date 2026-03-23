package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xlzd/gotp"
)

func TestMFAService_SetupTOTP(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")

	mfaRepo := new(mockMFARepo)
	rateLimiter := new(mockRateLimiter)
	
	jwtConfig := security.JWTConfig{
		SecretKey: []byte("test-secret"),
		Issuer:    "test",
	}
	
	svc := NewMFAService(nil, mfaRepo, nil, nil, nil, jwtConfig, rateLimiter)
	
	mfaRepo.On("Create", mock.Anything, mock.Anything).Return(nil)
	
	res, err := svc.SetupTOTP(context.Background(), "user-1", "user@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.Secret)
	assert.NotEmpty(t, res.QRCodeURL)
	mfaRepo.AssertExpectations(t)
}

func TestMFAService_VerifySetup(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")

	mfaRepo := new(mockMFARepo)
	rateLimiter := new(mockRateLimiter)
	
	jwtConfig := security.JWTConfig{
		SecretKey: []byte("test-secret"),
		Issuer:    "test",
	}
	
	svc := NewMFAService(nil, mfaRepo, nil, nil, nil, jwtConfig, rateLimiter)
	
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
	
	rateLimiter.On("Check", mock.Anything, mock.MatchedBy(func(cfg redis.RateLimitConfig) bool {
		return cfg.Key == "mfa_setup:user-1"
	})).Return(redis.RateLimitResult{Allowed: true}, nil)
	mfaRepo.On("FindInactiveByUser", mock.Anything, "user-1", "totp").Return(method, nil)
	mfaRepo.On("Activate", mock.Anything, "mfa-1").Return(nil)
	mfaRepo.On("SetBackupCodes", mock.Anything, "mfa-1", mock.Anything).Return(nil)
	
	res, err := svc.VerifySetup(context.Background(), "user-1", otpCode)
	assert.NoError(t, err)
	assert.Len(t, res.BackupCodes, 10)
	mfaRepo.AssertExpectations(t)
}

func TestMFAService_Challenge(t *testing.T) {
	mfaRepo := new(mockMFARepo)
	sessRepo := new(mockSessionRepo)
	rfRepo := new(mockRefreshTokenRepo)
	rateLimiter := new(mockRateLimiter)
	
	db, mockDB, _ := sqlmock.New()
	defer db.Close()
	
	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("test-secret-key-32-chars-long-!!!"),
		Issuer:       "test",
		AccessExpiry: 15 * time.Minute,
	}
	
	svc := NewMFAService(db, mfaRepo, nil, sessRepo, rfRepo, jwtConfig, rateLimiter)
	
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
	
	rateLimiter.On("Check", mock.Anything, mock.MatchedBy(func(cfg redis.RateLimitConfig) bool {
		return cfg.Key == "mfa_challenge:"+userID
	})).Return(redis.RateLimitResult{Allowed: true}, nil)
	mfaRepo.On("FindPrimaryActive", mock.Anything, userID).Return(method, nil)
	
	mockDB.ExpectBegin()
	sessRepo.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	rfRepo.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.ExpectCommit()
	
	res, err := svc.Challenge(context.Background(), mfaToken, otpCode, "127.0.0.1", "ua", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	mfaRepo.AssertExpectations(t)
	assert.NoError(t, mockDB.ExpectationsWereMet())
}
