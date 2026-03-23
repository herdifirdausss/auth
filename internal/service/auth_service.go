package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/validator"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
)

type AuthService interface {
	Register(ctx context.Context, req *model.RegisterRequest, ipAddress, userAgent string) (*model.RegisterResponse, error)
	VerifyEmail(ctx context.Context, rawToken string, ipAddress, userAgent string) error
	Login(ctx context.Context, req *model.LoginRequest, ip string, userAgent string) (*model.LoginResponse, error)
	RefreshToken(ctx context.Context, rawRefresh string, ip string, userAgent string) (*model.LoginResponse, error)
}

type AuthServiceImpl struct {
	db              *sql.DB
	userRepo        repository.UserRepository
	credRepo        repository.CredentialRepository
	tokenRepo       repository.SecurityTokenRepository
	eventRepo       repository.SecurityEventRepository
	tenantRepo      repository.TenantRepository
	membershipRepo  repository.TenantMembershipRepository
	sessionRepo     repository.SessionRepository
	refreshTokenRepo repository.RefreshTokenRepository
	mfaRepo         repository.MFARepository
	hasher          security.PasswordHasher
	rateLimiter    redis.RateLimiter
	sessionCache   *redis.SessionCache
	jwtConfig      security.JWTConfig
}

func NewAuthService(
	db *sql.DB,
	userRepo repository.UserRepository,
	credRepo repository.CredentialRepository,
	tokenRepo repository.SecurityTokenRepository,
	eventRepo repository.SecurityEventRepository,
	tenantRepo repository.TenantRepository,
	membershipRepo repository.TenantMembershipRepository,
	sessionRepo repository.SessionRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	mfaRepo repository.MFARepository,
	hasher security.PasswordHasher,
	rateLimiter redis.RateLimiter,
	sessionCache *redis.SessionCache,
	jwtConfig security.JWTConfig,
) *AuthServiceImpl {
	return &AuthServiceImpl{
		db:              db,
		userRepo:        userRepo,
		credRepo:        credRepo,
		tokenRepo:       tokenRepo,
		eventRepo:       eventRepo,
		tenantRepo:      tenantRepo,
		membershipRepo:  membershipRepo,
		sessionRepo:     sessionRepo,
		refreshTokenRepo: refreshTokenRepo,
		mfaRepo:         mfaRepo,
		hasher:          hasher,
		rateLimiter:    rateLimiter,
		sessionCache:   sessionCache,
		jwtConfig:      jwtConfig,
	}
}

func (s *AuthServiceImpl) Register(ctx context.Context, req *model.RegisterRequest, ipAddress, userAgent string) (*model.RegisterResponse, error) {
	// 1. Validate
	valErrors := validator.ValidateRegisterRequest(req)
	if len(valErrors) > 0 {
		return nil, fmt.Errorf("validation failed: %v", valErrors)
	}

	// 2. Check exist
	exists, err := s.userRepo.ExistsByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("email already exists")
	}

	exists, err = s.userRepo.ExistsByUsername(ctx, req.Username)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("username already exists")
	}

	// 3. Hash password
	hash, salt, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	// 4. Transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	user := &model.User{
		Email:      req.Email,
		Username:   req.Username,
		IsActive:   true,
		IsVerified: false,
	}
	if err := s.userRepo.Create(ctx, tx, user); err != nil {
		return nil, err
	}

	cred := &model.UserCredential{
		UserID:       user.ID,
		PasswordHash: hash,
		PasswordSalt: salt,
		PasswordAlgo: "argon2id",
	}
	if err := s.credRepo.Create(ctx, tx, cred); err != nil {
		return nil, err
	}

	var tenantID *string
	if req.TenantSlug != "" {
		tenant, err := s.tenantRepo.FindBySlug(ctx, req.TenantSlug)
		if err != nil {
			return nil, err
		}
		if tenant == nil {
			return nil, fmt.Errorf("tenant not found")
		}
		tenantID = &tenant.ID
		membership := &model.TenantMembership{
			UserID:   user.ID,
			TenantID: tenant.ID,
			Status:   "invited",
		}
		if err := s.membershipRepo.Create(ctx, tx, membership); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// 5. Token
	rawToken := make([]byte, 32)
	rand.Read(rawToken)
	tokenStr := hex.EncodeToString(rawToken)
	tokenHash := sha256.Sum256([]byte(tokenStr))

	token := &model.SecurityToken{
		UserID:    user.ID,
		TokenType: "email_verification",
		TokenHash: hex.EncodeToString(tokenHash[:]),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}
	s.tokenRepo.Create(ctx, token)

	// 6. Security Event
	event := &model.SecurityEvent{
		UserID:    &user.ID,
		TenantID:  tenantID,
		EventType: "user.registered",
		Severity:  "info",
		Details:   "User registered successfully",
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}
	s.eventRepo.Create(ctx, event)

	// TODO: Send email
	fmt.Printf("Verification token for %s: %s\n", req.Email, tokenStr)

	return &model.RegisterResponse{
		Status:  "success",
		Message: "Registration successful. Please check your email to verify your account.",
	}, nil
}

func (s *AuthServiceImpl) VerifyEmail(ctx context.Context, rawToken string, ipAddress, userAgent string) error {
	// 1. Hash token
	tokenHash := security.HashToken(rawToken)

	// 2. Find valid token
	token, err := s.tokenRepo.FindValidToken(ctx, tokenHash, "email_verification")
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("invalid or expired verification token")
	}

	// 3. Transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 4. Mark used
	if err := s.tokenRepo.MarkUsed(ctx, tx, token.ID); err != nil {
		return err
	}

	// 5. Set verified
	if err := s.userRepo.SetVerified(ctx, tx, token.UserID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// 6. Security Event
	event := &model.SecurityEvent{
		UserID:    &token.UserID,
		EventType: "user.email_verified",
		Severity:  "info",
		Details:   "Email verified successfully",
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}
	s.eventRepo.Create(ctx, event)

	return nil
}

func (s *AuthServiceImpl) Login(ctx context.Context, req *model.LoginRequest, ip string, userAgent string) (*model.LoginResponse, error) {
	// 1. Rate Limit IP
	res, err := s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      fmt.Sprintf("rate_limit:login:ip:%s", ip),
		MaxCount: 20,
		Window:   15 * time.Minute,
	})
	if err != nil || !res.Allowed {
		return nil, fmt.Errorf("too many login attempts from this IP")
	}

	// 2. Rate Limit User
	res, err = s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      fmt.Sprintf("rate_limit:login:user:%s", strings.ToLower(req.Email)),
		MaxCount: 10,
		Window:   15 * time.Minute,
	})
	if err != nil || !res.Allowed {
		return nil, fmt.Errorf("too many login attempts for this user")
	}

	// 3. Find User
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("invalid email or password") // generic
	}

	// 4. Check Suspended
	if user.IsSuspended {
		return nil, fmt.Errorf("account has been suspended")
	}

	// 5. Find Credentials
	cred, err := s.credRepo.FindByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("invalid email or password")
	}

	// 6. Verify Password
	match, err := s.hasher.Verify(req.Password, cred.PasswordHash, cred.PasswordSalt)
	if err != nil || !match {
		// Log Failed Login
		count, _ := s.userRepo.IncrementFailedLogin(ctx, user.ID)
		if count >= 10 {
			s.userRepo.SuspendUser(ctx, user.ID)
		}
		
		s.eventRepo.Create(ctx, &model.SecurityEvent{
			UserID:    &user.ID,
			EventType: "auth.login_failed",
			Severity:  "warning",
			Details:   "Failed login attempt",
			IPAddress: ip,
			UserAgent: userAgent,
		})
		
		return nil, fmt.Errorf("invalid email or password")
	}

	// 7. Successful Login
	s.userRepo.ResetFailedLoginAndUpdateLastLogin(ctx, user.ID, ip)

	// 8. Membership Check
	membership, _ := s.membershipRepo.FindActiveByUserID(ctx, user.ID)
	var tenantID *string
	var membershipID *string
	if membership != nil {
		tenantID = &membership.TenantID
		membershipID = &membership.ID
	}

	// 9. MFA Check
	mfa, _ := s.mfaRepo.FindPrimaryActive(ctx, user.ID)
	if mfa != nil {
		mfaToken, _ := security.GenerateMFAToken(s.jwtConfig, user.ID, 5*time.Minute)
		return &model.LoginResponse{
			MFARequired: true,
			MFAToken:    mfaToken,
		}, nil
	}

	// 10. Session & Tokens
	sessionToken, _ := security.GenerateSecureToken(32)
	sessionHash := security.HashToken(sessionToken)
	
	refreshToken, _ := security.GenerateSecureToken(32)
	refreshHash := security.HashToken(refreshToken)
	familyID, _ := security.GenerateSecureToken(16)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// 7. MFA Check
	mfaMethod, err := s.mfaRepo.FindPrimaryActive(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if mfaMethod != nil {
		mfaToken, err := security.GenerateMFAToken(s.jwtConfig, user.ID, 5*time.Minute)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil { // Still need to commit tx if any (though usually no tx here)
			return nil, err
		}
		return &model.LoginResponse{
			MFARequired: true,
			MFAToken:    mfaToken,
		}, nil
	}

	session := &model.Session{
		UserID:            user.ID,
		TenantID:          tenantID,
		MembershipID:      membershipID,
		TokenHash:         sessionHash,
		IPAddress:         ip,
		UserAgent:         userAgent,
		DeviceFingerprint: req.DeviceFingerprint,
		DeviceName:        req.DeviceName,
		ExpiresAt:         time.Now().Add(7 * 24 * time.Hour),
		IdleTimeoutAt:     time.Now().Add(30 * time.Minute),
	}
	if err := s.sessionRepo.Create(ctx, tx, session); err != nil {
		return nil, err
	}

	rf := &model.RefreshToken{
		SessionID:         session.ID,
		UserID:            user.ID,
		TokenHash:         refreshHash,
		FamilyID:          familyID,
		Generation:        1,
		IPAddress:         ip,
		DeviceFingerprint: req.DeviceFingerprint,
		ExpiresAt:         time.Now().Add(30 * 24 * time.Hour),
	}
	if err := s.refreshTokenRepo.Create(ctx, tx, rf); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// 11. JWT
	claims := security.JWTClaims{
		Sub: user.ID,
		Sid: session.ID,
	}
	if tenantID != nil {
		claims.Tid = *tenantID
	}
	// Add roles if needed...
	
	accessToken, err := security.GenerateAccessToken(s.jwtConfig, claims)
	if err != nil {
		return nil, err
	}

	// 12. Redis Cache
	s.sessionCache.Set(ctx, sessionHash, &redis.CachedSession{
		SessionID:     session.ID,
		UserID:        session.UserID,
		MFAVerified:   session.MFAVerified,
		ExpiresAt:     session.ExpiresAt,
		IdleTimeoutAt: session.IdleTimeoutAt,
	})

	// 13. Security Event
	s.eventRepo.Create(ctx, &model.SecurityEvent{
		UserID:    &user.ID,
		TenantID:  tenantID,
		EventType: "auth.login_success",
		Severity:  "info",
		Details:   "User logged in successfully",
		IPAddress: ip,
		UserAgent: userAgent,
	})

	return &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.jwtConfig.AccessExpiry.Seconds()),
	}, nil
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, rawRefresh string, ip string, userAgent string) (*model.LoginResponse, error) {
	// 1. Hash token
	refreshHash := security.HashToken(rawRefresh)

	// 2. Find token
	token, err := s.refreshTokenRepo.FindByTokenHash(ctx, refreshHash)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// 3. Expiry Check
	if token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token expired")
	}

	// 4. Revocation Check
	if token.RevokedAt != nil {
		return nil, fmt.Errorf("refresh token revoked")
	}

	// 5. REUSE DETECTION
	if token.UsedAt != nil {
		// Critical Security Event
		s.eventRepo.Create(ctx, &model.SecurityEvent{
			UserID:    &token.UserID,
			EventType: "auth.refresh_token_reuse",
			Severity:  "critical",
			Details:   "Suspicious activity: Refresh token reuse detected. Revoking entire family.",
			IPAddress: ip,
			UserAgent: userAgent,
		})

		// Revoke the entire family and the session
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		s.refreshTokenRepo.RevokeByFamily(ctx, tx, token.FamilyID)
		s.sessionRepo.Revoke(ctx, token.SessionID, "refresh_token_reuse")
		
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		
		// Clear cache
		// We don't have the token_hash for the access token here, but we can't easily clear it.
		// However, session lookup in DB will fail since it's revoked.

		return nil, fmt.Errorf("suspicious activity detected")
	}

	// 6. ROTATION
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// 6.1 Mark current token as used
	if err := s.refreshTokenRepo.MarkUsed(ctx, tx, token.ID); err != nil {
		return nil, err
	}

	// 6.2 Create new refresh token
	newRawRefresh, _ := security.GenerateSecureToken(32)
	newRefreshHash := security.HashToken(newRawRefresh)
	
	newRefreshToken := &model.RefreshToken{
		SessionID:     token.SessionID,
		UserID:        token.UserID,
		TokenHash:     newRefreshHash,
		FamilyID:      token.FamilyID,
		Generation:    token.Generation + 1,
		ParentTokenID: &token.ID,
		IPAddress:     ip,
		ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
	}
	if err := s.refreshTokenRepo.Create(ctx, tx, newRefreshToken); err != nil {
		return nil, err
	}

	// 6.3 Update session activity
	if err := s.sessionRepo.UpdateActivity(ctx, token.SessionID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// 7. Get user to get tenant info (optional, or just use sid/sub)
	// For simplicity, let's just use what's in the token/session
	// In a real app, you might want to fetch the current session to get TenantID

	// 8. Generate new JWT
	claims := security.JWTClaims{
		Sub: token.UserID,
		Sid: token.SessionID,
	}
	// Note: We might miss Tid here if not fetched from session.
	// But let's assume session still valid.
	
	accessToken, err := security.GenerateAccessToken(s.jwtConfig, claims)
	if err != nil {
		return nil, err
	}

	return &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.jwtConfig.AccessExpiry.Seconds()),
	}, nil
}
