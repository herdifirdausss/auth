package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/xlzd/gotp"
	"github.com/jackc/pgx/v5"
	"go.uber.org/mock/gomock"
)

func TestMFAService_SetupTOTP(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfaRepo := mocks.NewMockMFARepository(ctrl)
	mockDB := mocks.NewMockTransactor(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey: []byte("test-secret"),
		Issuer:    "test",
	}

	svc := NewMFAService(mockDB, mfaRepo, nil, nil, nil, nil, jwtConfig, rateLimiter, nil, nil, utils.RealClock{}, slog.Default())

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
	mockDB := mocks.NewMockTransactor(ctrl)
	mockTx := mocks.NewMockTx(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey: []byte("test-secret"),
		Issuer:    "test",
	}

	svc := NewMFAService(mockDB, mfaRepo, nil, nil, nil, nil, jwtConfig, rateLimiter, nil, nil, utils.RealClock{}, slog.Default())

	encryptionKey := "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
	secret := "JBSWY3DPEHPK3PXP"
	encryptedSecret, _ := security.Encrypt(secret, encryptionKey)

	method := &model.MFAMethod{
		ID:              "mfa-1",
		UserID:          "user-1",
		SecretEncrypted: encryptedSecret,
	}

	totp := gotp.NewDefaultTOTP(secret)
	otpCode := totp.Now()

	rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil)
	mfaRepo.EXPECT().FindInactiveByUser(gomock.Any(), "user-1", "totp").Return(method, nil)

	mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
	mfaRepo.EXPECT().Activate(gomock.Any(), mockTx, "mfa-1").Return(nil)
	mfaRepo.EXPECT().SetBackupCodes(gomock.Any(), mockTx, "mfa-1", gomock.Any()).Return(nil)
	mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
	mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	res, err := svc.VerifySetup(context.Background(), "user-1", otpCode)
	assert.NoError(t, err)
	assert.Len(t, res.BackupCodes, 10)
}

func TestMFAService_Challenge_Success(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfaRepo := mocks.NewMockMFARepository(ctrl)
	mockDB := mocks.NewMockTransactor(ctrl)
	mockTx := mocks.NewMockTx(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)
	membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)
	sessionCache := mocks.NewMockSessionCache(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("test-secret-key-32-chars-long-!!!"),
		Issuer:       "test",
		AccessExpiry: 15 * time.Minute,
	}

	svc := NewMFAService(mockDB, mfaRepo, nil, sessRepo, rfRepo, membershipRepo, jwtConfig, rateLimiter, sessionCache, nil, utils.RealClock{}, slog.Default())

	userID := "user-1"
	mfaToken, _ := security.GenerateMFAToken(jwtConfig, userID, 5*time.Minute)
	secret := "JBSWY3DPEHPK3PXP"
	encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	method := &model.MFAMethod{ID: "mfa-1", UserID: userID, SecretEncrypted: encryptedSecret}

	rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
	mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), userID).Return(method, nil)
	membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), userID).Return(&model.TenantMembership{ID: "mem-1", TenantID: "ten-1"}, nil)

	mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
	mfaRepo.EXPECT().IncrementUseCount(gomock.Any(), mockTx, "mfa-1").Return(nil)
	sessRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx pgx.Tx, s *model.Session) error {
		s.ID = "sess-1"
		return nil
	})
	rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil)
	mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
	mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()
	sessionCache.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	res, err := svc.Challenge(context.Background(), model.ChallengeRequest{
		MFAToken: mfaToken,
		OTPCode:  gotp.NewDefaultTOTP(secret).Now(),
	}, "127.0.0.1", "ua", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
}

func TestMFAService_Challenge_RecoverySuccess(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfaRepo := mocks.NewMockMFARepository(ctrl)
	mockDB := mocks.NewMockTransactor(ctrl)
	mockTx := mocks.NewMockTx(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)
	membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("test-secret-key-32-chars-long-!!!"),
		Issuer:       "test",
		AccessExpiry: 15 * time.Minute,
	}

	svc := NewMFAService(mockDB, mfaRepo, nil, sessRepo, rfRepo, membershipRepo, jwtConfig, rateLimiter, nil, nil, utils.RealClock{}, slog.Default())

	userID := "user-1"
	mfaToken, _ := security.GenerateMFAToken(jwtConfig, userID, 5*time.Minute)

	// Create hashed backup codes in JSON format
	code1Hash := security.HashToken("code1")
	code2Hash := security.HashToken("code2")
	jsonData := fmt.Sprintf(`["%s","%s"]`, code1Hash, code2Hash)
	encryptedCodes, _ := security.Encrypt(jsonData, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")

	method := &model.MFAMethod{ID: "mfa-1", UserID: userID, BackupCodesEncrypted: utils.Ptr(encryptedCodes)}

	rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
	mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), userID).Return(method, nil)
	membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), userID).Return(&model.TenantMembership{ID: "mem-1", TenantID: "ten-1"}, nil)

	mfaRepo.EXPECT().SetBackupCodes(gomock.Any(), gomock.Nil(), "mfa-1", gomock.Any()).Return(nil)
	mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
	mfaRepo.EXPECT().IncrementUseCount(gomock.Any(), mockTx, "mfa-1").Return(nil)
	sessRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx pgx.Tx, s *model.Session) error {
		s.ID = "sess-1"
		return nil
	})
	rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil)
	mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
	mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	res, err := svc.Challenge(context.Background(), model.ChallengeRequest{
		MFAToken:     mfaToken,
		RecoveryCode: "code1",
	}, "127.0.0.1", "ua", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
}

func TestMFAService_Challenge_Fails(t *testing.T) {
	os.Setenv("MFA_ENCRYPTION_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	defer os.Unsetenv("MFA_ENCRYPTION_KEY")
	os.Unsetenv("MFA_TEST_MODE")

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("test-secret-key-32-chars-long-!!!"),
		Issuer:       "test",
		AccessExpiry: 15 * time.Minute,
	}

	tests := []struct {
		name          string
		setupMocks    func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache)
		request       model.ChallengeRequest
		expectedError string
	}{
		{
			name: "Invalid Token",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
			},
			request:       model.ChallengeRequest{MFAToken: "invalid"},
			expectedError: "invalid or expired mfa token",
		},
		{
			name: "Anti-Replay Triggered",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: false}, nil)
			},
			request:       model.ChallengeRequest{MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }()},
			expectedError: "mfa challenge already processed or replayed",
		},
		{
			name: "Rate Limit Exceeded",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil)  // Replay check passes
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: false}, nil) // Rate limit fails
			},
			request:       model.ChallengeRequest{MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }()},
			expectedError: "too many attempts, try again later",
		},
		{
			name: "MFA Repo Find Error",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(nil, fmt.Errorf("repo error"))
			},
			request:       model.ChallengeRequest{MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }()},
			expectedError: "repo error",
		},
		{
			name: "MFA Not Enabled",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(nil, nil)
			},
			request:       model.ChallengeRequest{MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }()},
			expectedError: "mfa not enabled for this user",
		},
		{
			name: "Missing OTP Code",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{}, nil)
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  "",
			},
			expectedError: "otp code is required",
		},
		{
			name: "Secret Decrypt Failure",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{SecretEncrypted: "abcd"}, nil)
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  "123456",
			},
			expectedError: "ciphertext too short",
		},
		{
			name: "Invalid OTP",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{SecretEncrypted: encryptedSecret}, nil)
			},
			request:       model.ChallengeRequest{MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(), OTPCode: "111111"},
			expectedError: "invalid OTP code",
		},
		{
			name: "Membership Repo Find Error",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{SecretEncrypted: encryptedSecret}, nil)
				membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "u1").Return(nil, fmt.Errorf("membership repo error"))
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now(),
			},
			expectedError: "membership repo error",
		},
		{
			name: "Membership Not Found",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{SecretEncrypted: encryptedSecret}, nil)
				membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "u1").Return(nil, nil)
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now(),
			},
			expectedError: "user has no active tenant membership",
		},
		{
			name: "DB Begin Failure",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{SecretEncrypted: encryptedSecret}, nil)
				membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "u1").Return(&model.TenantMembership{}, nil)
				db.EXPECT().Begin(gomock.Any()).Return(nil, fmt.Errorf("DB error"))
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now(),
			},
			expectedError: "DB error",
		},
		{
			name: "Session Creation Failure",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{ID: "m1", SecretEncrypted: encryptedSecret}, nil)
				membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "u1").Return(&model.TenantMembership{}, nil)

				mockTx := mocks.NewMockTx(gomock.NewController(t))
				db.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
				mfaRepo.EXPECT().IncrementUseCount(gomock.Any(), mockTx, "m1").Return(nil)
				sessRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(fmt.Errorf("session error"))
				mockTx.EXPECT().Rollback(gomock.Any()).Return(nil)
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now(),
			},
			expectedError: "session error",
		},
		{
			name: "Refresh Token Creation Failure",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{ID: "m1", SecretEncrypted: encryptedSecret}, nil)
				membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "u1").Return(&model.TenantMembership{}, nil)

				mockTx := mocks.NewMockTx(gomock.NewController(t))
				db.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
				mfaRepo.EXPECT().IncrementUseCount(gomock.Any(), mockTx, "m1").Return(nil)
				sessRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx pgx.Tx, s *model.Session) error {
					s.ID = "sess-1"
					s.TenantID = utils.Ptr("t1")
					return nil
				})
				rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(fmt.Errorf("rf error"))
				mockTx.EXPECT().Rollback(gomock.Any()).Return(nil)
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now(),
			},
			expectedError: "rf error",
		},
		{
			name: "Commit Failure",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{ID: "m1", SecretEncrypted: encryptedSecret}, nil)
				membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "u1").Return(&model.TenantMembership{}, nil)

				mockTx := mocks.NewMockTx(gomock.NewController(t))
				db.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
				mfaRepo.EXPECT().IncrementUseCount(gomock.Any(), mockTx, "m1").Return(nil)
				sessRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx pgx.Tx, s *model.Session) error {
					s.ID = "sess-1"
					s.TenantID = utils.Ptr("t1")
					return nil
				})
				rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil)
				mockTx.EXPECT().Commit(gomock.Any()).Return(fmt.Errorf("commit error"))
				mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now(),
			},
			expectedError: "commit error",
		},
		{
			name: "Empty Recovery Code List",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{BackupCodesEncrypted: utils.Ptr("")}, nil)
			},
			request: model.ChallengeRequest{
				MFAToken:     func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				RecoveryCode: "code1",
			},
			expectedError: "no recovery codes configured",
		},
		{
			name: "Recovery Decrypt Failure",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{BackupCodesEncrypted: utils.Ptr("abcd")}, nil)
			},
			request: model.ChallengeRequest{
				MFAToken:     func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				RecoveryCode: "code1",
			},
			expectedError: "failed to decrypt recovery codes",
		},
		{
			name: "Recovery Code Not Found",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				codes, _ := security.Encrypt(`["h2","h3"]`, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{BackupCodesEncrypted: utils.Ptr(codes)}, nil)
			},
			request: model.ChallengeRequest{
				MFAToken:     func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				RecoveryCode: "c1",
			},
			expectedError: "invalid recovery code",
		},
		{
			name: "SetBackupCodes Failure",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				h1 := security.HashToken("c1")
				codes, _ := security.Encrypt(fmt.Sprintf(`["%s","h2"]`, h1), "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{ID: "m1", BackupCodesEncrypted: utils.Ptr(codes)}, nil)
				mfaRepo.EXPECT().SetBackupCodes(gomock.Any(), gomock.Nil(), "m1", gomock.Any()).Return(fmt.Errorf("set backup error"))
			},
			request: model.ChallengeRequest{
				MFAToken:     func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				RecoveryCode: "c1",
			},
			expectedError: "set backup error",
		},
		{
			name: "Replay Check Error",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{}, fmt.Errorf("redis error"))
			},
			request:       model.ChallengeRequest{MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }()},
			expectedError: "redis error",
		},
		{
			name: "Rate Limit Check Error",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil) // Replay check passes
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{}, fmt.Errorf("redis limit error"))
			},
			request:       model.ChallengeRequest{MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }()},
			expectedError: "redis limit error",
		},
		{
			name: "Challenge with Session Cache",
			setupMocks: func(mfaRepo *mocks.MockMFARepository, rateLimiter *mocks.MockRateLimiter, membershipRepo *mocks.MockTenantMembershipRepository, db *mocks.MockTransactor, sessRepo *mocks.MockSessionRepository, rfRepo *mocks.MockRefreshTokenRepository, sessionCache *mocks.MockSessionCache) {
				rateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(redis.RateLimitResult{Allowed: true}, nil).AnyTimes()
				secret := "JBSWY3DPEHPK3PXP"
				encryptedSecret, _ := security.Encrypt(secret, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
				mfaRepo.EXPECT().FindPrimaryActive(gomock.Any(), "u1").Return(&model.MFAMethod{ID: "m1", SecretEncrypted: encryptedSecret}, nil).AnyTimes()
				membershipRepo.EXPECT().FindActiveByUserID(gomock.Any(), "u1").Return(&model.TenantMembership{}, nil).AnyTimes()

				mockTx := mocks.NewMockTx(gomock.NewController(t))
				db.EXPECT().Begin(gomock.Any()).Return(mockTx, nil).AnyTimes()
				mfaRepo.EXPECT().IncrementUseCount(gomock.Any(), mockTx, "m1").Return(nil).AnyTimes()
				sessRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).DoAndReturn(func(ctx context.Context, tx pgx.Tx, s *model.Session) error {
					s.ID = "sess-1"
					s.TenantID = utils.Ptr("t1")
					return nil
				})
				rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil).AnyTimes()
				mockTx.EXPECT().Commit(gomock.Any()).Return(nil).AnyTimes()
				mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

				sessionCache.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any()).Return(fmt.Errorf("cache error"))
			},
			request: model.ChallengeRequest{
				MFAToken: func() string { t, _ := security.GenerateMFAToken(jwtConfig, "u1", 1*time.Minute); return t }(),
				OTPCode:  gotp.NewDefaultTOTP("JBSWY3DPEHPK3PXP").Now(),
			},
			expectedError: "cache error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mfaRepo := mocks.NewMockMFARepository(ctrl)
			mockDB := mocks.NewMockTransactor(ctrl)
			rateLimiter := mocks.NewMockRateLimiter(ctrl)
			membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)
			sessRepo := mocks.NewMockSessionRepository(ctrl)
			rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
			sessionCache := mocks.NewMockSessionCache(ctrl)

			svc := NewMFAService(mockDB, mfaRepo, nil, sessRepo, rfRepo, membershipRepo, jwtConfig, rateLimiter, sessionCache, nil, utils.RealClock{}, slog.Default())

			tt.setupMocks(mfaRepo, rateLimiter, membershipRepo, mockDB, sessRepo, rfRepo, sessionCache)

			_, err := svc.Challenge(context.Background(), tt.request, "127.0.0.1", "ua", "")
			if tt.name == "Challenge with Session Cache" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

func TestMFAService_DisableMFA(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mfaRepo := mocks.NewMockMFARepository(ctrl)
	mockDB := mocks.NewMockTransactor(ctrl)
	svc := NewMFAService(mockDB, mfaRepo, nil, nil, nil, nil, security.JWTConfig{}, nil, nil, nil, utils.RealClock{}, slog.Default())

	mfaRepo.EXPECT().DeactivateAll(gomock.Any(), "user-1").Return(nil)

	err := svc.DisableMFA(context.Background(), "user-1")
	assert.NoError(t, err)
}
