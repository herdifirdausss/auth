package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/utils"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type MFAService interface {
	SetupTOTP(ctx context.Context, userID, email string) (*model.SetupResponse, error)
	VerifySetup(ctx context.Context, userID, otpCode string) (*model.VerifySetupResponse, error)
	Challenge(ctx context.Context, req model.ChallengeRequest, ip, ua, fingerprint string) (*model.LoginResponse, error)
	DisableMFA(ctx context.Context, userID string) error
}

type MFAServiceImpl struct {
	db             repository.Transactor
	mfaRepo        repository.MFARepository
	userRepo       repository.UserRepository
	sessRepo       repository.SessionRepository
	rfRepo         repository.RefreshTokenRepository
	membershipRepo repository.TenantMembershipRepository
	jwtConfig      security.JWTConfig
	rateLimiter    redis.RateLimiter
	sessionCache   redis.SessionCache
	clock          utils.Clock
	encryptionKey  string
	logger         *slog.Logger
}

func NewMFAService(
	db repository.Transactor,
	mfaRepo repository.MFARepository,
	userRepo repository.UserRepository,
	sessRepo repository.SessionRepository,
	rfRepo repository.RefreshTokenRepository,
	membershipRepo repository.TenantMembershipRepository,
	jwtConfig security.JWTConfig,
	rateLimiter redis.RateLimiter,
	sessionCache redis.SessionCache,
	clock utils.Clock,
	logger *slog.Logger,
) *MFAServiceImpl {
	key := os.Getenv("MFA_ENCRYPTION_KEY")
	if key == "" {
		key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
	}
	return &MFAServiceImpl{
		db:             db,
		mfaRepo:        mfaRepo,
		userRepo:       userRepo,
		sessRepo:       sessRepo,
		rfRepo:         rfRepo,
		membershipRepo: membershipRepo,
		jwtConfig:      jwtConfig,
		rateLimiter:    rateLimiter,
		sessionCache:   sessionCache,
		clock:          clock,
		encryptionKey:  key,
		logger:         logger,
	}
}

func (s *MFAServiceImpl) SetupTOTP(ctx context.Context, userID, email string) (*model.SetupResponse, error) {
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}

	encryptedSecret, err := security.Encrypt(secret, s.encryptionKey)
	if err != nil {
		return nil, err
	}

	method := &model.MFAMethod{
		UserID:          userID,
		MethodType:      "totp",
		MethodName:      "Authenticator App",
		SecretEncrypted: encryptedSecret,
		IsActive:        false,
		IsPrimary:       false,
	}

	// Check if already has inactive TOTP, if so, delete or update (simplified: just create new)
	if err := s.mfaRepo.Create(ctx, method); err != nil {
		return nil, err
	}

	qrCodeURL := security.GenerateQRCodeURL(secret, email, "AuthMVP")
	s.logger.Info("Integration test: MFA setup secret generated", "email", email, "secret", secret)

	return &model.SetupResponse{
		Secret:    secret,
		QRCodeURL: qrCodeURL,
	}, nil
}

func (s *MFAServiceImpl) VerifySetup(ctx context.Context, userID, otpCode string) (*model.VerifySetupResponse, error) {
	// Rate limit OTP verification
	limitRet, err := s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      "mfa_setup:" + userID,
		MaxCount: 5,
		Window:   10 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	if !limitRet.Allowed {
		return nil, fmt.Errorf("too many attempts, try again later")
	}

	method, err := s.mfaRepo.FindInactiveByUser(ctx, userID, "totp")
	if err != nil {
		return nil, err
	}
	if method == nil {
		return nil, fmt.Errorf("no pending MFA setup found")
	}

	secret, err := security.Decrypt(method.SecretEncrypted, s.encryptionKey)
	if err != nil {
		return nil, err
	}

	// MFA_TEST_MODE: allow "000000" for automated tests
	if os.Getenv("MFA_TEST_MODE") == "true" && otpCode == "000000" {
		// Bypass real TOTP check
	} else {
		if !security.VerifyTOTP(secret, otpCode) {
			return nil, fmt.Errorf("invalid OTP code")
		}
	}

	if err := s.mfaRepo.Activate(ctx, method.ID); err != nil {
		return nil, err
	}

	backupCodes, err := security.GenerateBackupCodes(10)
	if err != nil {
		return nil, err
	}

	// Simplified: store backup codes as comma-separated encrypted string
	// In production, should hash each code.
	var codesJoined string
	for i, c := range backupCodes {
		if i > 0 {
			codesJoined += ","
		}
		codesJoined += c
	}
	encryptedCodes, _ := security.Encrypt(codesJoined, s.encryptionKey)
	s.mfaRepo.SetBackupCodes(ctx, method.ID, encryptedCodes)

	return &model.VerifySetupResponse{
		BackupCodes: backupCodes,
	}, nil
}

func (s *MFAServiceImpl) Challenge(ctx context.Context, req model.ChallengeRequest, ip, ua, fingerprint string) (*model.LoginResponse, error) {
	claims, err := security.ValidateMFAToken(s.jwtConfig, req.MFAToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired mfa token")
	}
	
	mfaToken := req.MFAToken
	otpCode := req.OTPCode
	recoveryCode := req.RecoveryCode

	userID := claims.Sub // Sub is the UserID in MFAToken

	// Anti-replay: check if mfaToken was already used
	mfaTokenHash := security.HashToken(mfaToken)
	replayRet, err := s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      "mfa_replay:" + mfaTokenHash,
		MaxCount: 1,
		Window:   5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	if !replayRet.Allowed {
		return nil, fmt.Errorf("mfa challenge already processed or replayed")
	}

	// Rate limit challenge
	limitRet, err := s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      "mfa_challenge:" + userID,
		MaxCount: 5,
		Window:   10 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	if !limitRet.Allowed {
		return nil, fmt.Errorf("too many attempts, try again later")
	}

	method, err := s.mfaRepo.FindPrimaryActive(ctx, userID)
	if err != nil {
		return nil, err
	}
	if method == nil {
		return nil, fmt.Errorf("mfa not enabled for this user")
	}

	// 3. Verify either OTP or Recovery Code
	if recoveryCode != "" {
		if err := s.verifyRecoveryCode(ctx, method, recoveryCode); err != nil {
			return nil, err
		}
	} else {
		if otpCode == "" {
			return nil, fmt.Errorf("otp code is required")
		}

		secret, err := security.Decrypt(method.SecretEncrypted, s.encryptionKey)
		if err != nil {
			return nil, err
		}

		// MFA_TEST_MODE: allow "000000" for automated tests
		if os.Getenv("MFA_TEST_MODE") == "true" && otpCode == "000000" {
			// Bypass real TOTP check
		} else {
			if !security.VerifyTOTPAtTime(secret, otpCode, s.clock.Now()) {
				return nil, fmt.Errorf("invalid OTP code")
			}
		}
	}

	// 4a. Get User Tenant
	membership, err := s.membershipRepo.FindActiveByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if membership == nil {
		return nil, fmt.Errorf("user has no active tenant membership")
	}

	// Success: Create session in tx
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// 4b. Generate Session & Refresh Tokens
	sessionToken, _ := security.GenerateSecureToken(32)
	sessionHash := security.HashToken(sessionToken)

	refreshToken, _ := security.GenerateSecureToken(32)
	refreshHash := security.HashToken(refreshToken)
	familyID, _ := security.GenerateSecureToken(16)

	session := &model.Session{
		UserID:            userID,
		TenantID:          &membership.TenantID,
		MembershipID:      &membership.ID,
		TokenHash:         sessionHash,
		IPAddress:         ip,
		UserAgent:         ua,
		DeviceFingerprint: fingerprint,
		MFAVerified:       true,
		ExpiresAt:         s.clock.Now().Add(7 * 24 * time.Hour),
		IdleTimeoutAt:     s.clock.Now().Add(30 * time.Minute),
	}

	if err := s.sessRepo.Create(ctx, tx, session); err != nil {
		return nil, err
	}

	// Create refresh token family
	rf := &model.RefreshToken{
		SessionID:  session.ID,
		UserID:     userID,
		TokenHash:  refreshHash,
		FamilyID:   familyID,
		Generation: 1,
		IPAddress:  ip,
		UserAgent:  ua,
		ExpiresAt:  s.clock.Now().Add(30 * 24 * time.Hour),
	}

	if err := s.rfRepo.Create(ctx, tx, rf); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	// 6. Cache Session in Redis
	if s.sessionCache != nil {
		cached := &redis.CachedSession{
			SessionID:     session.ID,
			UserID:        session.UserID,
			MFAVerified:   true,
			ExpiresAt:     session.ExpiresAt,
			IdleTimeoutAt: session.IdleTimeoutAt,
		}
		if err := s.sessionCache.Set(ctx, session.ID, cached); err != nil {
			s.logger.ErrorContext(ctx, "Error caching session in mfa challenge", "session_id", session.ID, "error", err)
		}
	}

	accessToken, _ := security.GenerateAccessToken(s.jwtConfig, security.JWTClaims{
		Sub: userID,
		Sid: session.ID,
		Tid: *session.TenantID,
	})

	return &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

func (s *MFAServiceImpl) DisableMFA(ctx context.Context, userID string) error {
	return s.mfaRepo.DeactivateAll(ctx, userID)
}

func (s *MFAServiceImpl) verifyRecoveryCode(ctx context.Context, method *model.MFAMethod, code string) error {
	if method.BackupCodesEncrypted == "" {
		return fmt.Errorf("no recovery codes configured")
	}

	decryptedCodes, err := security.Decrypt(method.BackupCodesEncrypted, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt recovery codes")
	}

	// Simplified: comma-separated list of codes
	// TODO: Replace with hashed individual codes as per hardening plan
	codes := strings.Split(decryptedCodes, ",")
	found := false
	var remaining []string
	for _, c := range codes {
		if c == code {
			found = true
		} else {
			remaining = append(remaining, c)
		}
	}

	if !found {
		return fmt.Errorf("invalid recovery code")
	}

	// Update remaining codes
	newEncrypted, _ := security.Encrypt(strings.Join(remaining, ","), s.encryptionKey)
	return s.mfaRepo.SetBackupCodes(ctx, method.ID, newEncrypted)
}
