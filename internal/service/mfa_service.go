package service

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type MFAService interface {
	SetupTOTP(ctx context.Context, userID, email string) (*model.SetupResponse, error)
	VerifySetup(ctx context.Context, userID, otpCode string) (*model.VerifySetupResponse, error)
	Challenge(ctx context.Context, mfaToken, otpCode string, ip, ua, fingerprint string) (*model.LoginResponse, error)
}

type MFAServiceImpl struct {
	db           repository.Transactor
	mfaRepo      repository.MFARepository
	userRepo     repository.UserRepository
	sessRepo     repository.SessionRepository
	rfRepo       repository.RefreshTokenRepository
	jwtConfig    security.JWTConfig
	rateLimiter   redis.RateLimiter
	encryptionKey string
}

func NewMFAService(
	db repository.Transactor,
	mfaRepo repository.MFARepository,
	userRepo repository.UserRepository,
	sessRepo repository.SessionRepository,
	rfRepo repository.RefreshTokenRepository,
	jwtConfig security.JWTConfig,
	rateLimiter redis.RateLimiter,
) *MFAServiceImpl {
	key := os.Getenv("MFA_ENCRYPTION_KEY")
	if key == "" {
		// FALLBACK for development (NOT for production!)
		key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=" // 32 bytes base64
	}
	return &MFAServiceImpl{
		db:            db,
		mfaRepo:       mfaRepo,
		userRepo:      userRepo,
		sessRepo:      sessRepo,
		rfRepo:        rfRepo,
		jwtConfig:     jwtConfig,
		rateLimiter:   rateLimiter,
		encryptionKey: key,
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

	if !security.VerifyTOTP(secret, otpCode) {
		return nil, fmt.Errorf("invalid OTP code")
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

func (s *MFAServiceImpl) Challenge(ctx context.Context, mfaToken, otpCode string, ip, ua, fingerprint string) (*model.LoginResponse, error) {
	claims, err := security.ValidateMFAToken(s.jwtConfig, mfaToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired mfa token")
	}

	userID := claims.Sub // Sub is the UserID in MFAToken

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

	secret, err := security.Decrypt(method.SecretEncrypted, s.encryptionKey)
	if err != nil {
		return nil, err
	}

	if !security.VerifyTOTP(secret, otpCode) {
		return nil, fmt.Errorf("invalid OTP code")
	}

	// Success: Create session in tx
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	session := &model.Session{
		UserID:            userID,
		IPAddress:         ip,
		UserAgent:         ua,
		DeviceFingerprint: fingerprint,
		MFAVerified:       true,
		ExpiresAt:         time.Now().Add(7 * 24 * time.Hour),
		IdleTimeoutAt:     time.Now().Add(30 * time.Minute),
	}
	
	if err := s.sessRepo.Create(ctx, tx, session); err != nil {
		return nil, err
	}

	// Create refresh token family
	familyID, _ := security.GenerateSecureToken(16)
	rawRefresh, _ := security.GenerateSecureToken(32)
	refreshHash := security.HashToken(rawRefresh)
	
	rf := &model.RefreshToken{
		SessionID:  session.ID,
		UserID:     userID,
		TokenHash:  refreshHash,
		FamilyID:   familyID,
		Generation: 1,
		IPAddress:  ip,
		UserAgent:  ua,
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
	}
	
	if err := s.rfRepo.Create(ctx, tx, rf); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	accessToken, _ := security.GenerateAccessToken(s.jwtConfig, security.JWTClaims{
		Sub: userID,
		Sid: session.ID,
	})

	return &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

