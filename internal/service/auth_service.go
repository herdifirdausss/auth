package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/validator"
)

//go:generate mockgen -source=auth_service.go -destination=../mocks/mock_auth_service.go -package=mocks
type AuthService interface {
	Register(ctx context.Context, req *model.RegisterRequest, ipAddress, userAgent string) (*model.RegisterResponse, error)
	VerifyEmail(ctx context.Context, rawToken string, ipAddress, userAgent string) error
	Login(ctx context.Context, req *model.LoginRequest, ip, userAgent string) (*model.LoginResponse, error)
	RefreshToken(ctx context.Context, req *model.RefreshTokenRequest, ip, userAgent string) (*model.LoginResponse, error)
	Logout(ctx context.Context, sessionID, userID, tokenHash string) error
	LogoutAll(ctx context.Context, userID string) error
	ValidateSession(ctx context.Context, sessionID string) (*model.Session, error)
	ForgotPassword(ctx context.Context, email string, ip, userAgent string) error
	ResetPassword(ctx context.Context, token, newPassword, ip, userAgent string) error
	DeleteAccount(ctx context.Context, userID, ip, userAgent string) error
}

type AuthServiceImpl struct {
	db                  repository.Pool
	userRepo            repository.UserRepository
	credRepo            repository.CredentialRepository
	tokenRepo           repository.SecurityTokenRepository
	eventRepo           repository.SecurityEventRepository
	tenantRepo          repository.TenantRepository
	membershipRepo      repository.TenantMembershipRepository
	sessionRepo         repository.SessionRepository
	refreshTokenRepo    repository.RefreshTokenRepository
	mfaRepo             repository.MFARepository
	passwordHistoryRepo repository.PasswordHistoryRepository
	trustedDeviceRepo   repository.TrustedDeviceRepository
	roleRepo            repository.RoleRepository
	membershipRoleRepo  repository.MembershipRoleRepository
	riskService         RiskService
	pwnedValidator      security.PwnedValidator
	auditService        AuditService
	hasher              security.PasswordHasher
	rateLimiter         redis.RateLimiter
	sessionCache        redis.SessionCache
	jwtConfig           security.JWTConfig
	logger              *slog.Logger
}

func NewAuthService(
	db repository.Pool,
	userRepo repository.UserRepository,
	credRepo repository.CredentialRepository,
	tokenRepo repository.SecurityTokenRepository,
	eventRepo repository.SecurityEventRepository,
	tenantRepo repository.TenantRepository,
	membershipRepo repository.TenantMembershipRepository,
	sessionRepo repository.SessionRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	mfaRepo repository.MFARepository,
	passwordHistoryRepo repository.PasswordHistoryRepository,
	trustedDeviceRepo repository.TrustedDeviceRepository,
	roleRepo repository.RoleRepository,
	membershipRoleRepo repository.MembershipRoleRepository,
	riskService RiskService,
	pwnedValidator security.PwnedValidator,
	auditService AuditService,
	hasher security.PasswordHasher,
	rateLimiter redis.RateLimiter,
	sessionCache redis.SessionCache,
	jwtConfig security.JWTConfig,
	logger *slog.Logger,
) AuthService {
	return &AuthServiceImpl{
		db:                  db,
		userRepo:            userRepo,
		credRepo:            credRepo,
		tokenRepo:           tokenRepo,
		eventRepo:           eventRepo,
		tenantRepo:          tenantRepo,
		membershipRepo:      membershipRepo,
		sessionRepo:         sessionRepo,
		refreshTokenRepo:    refreshTokenRepo,
		mfaRepo:             mfaRepo,
		passwordHistoryRepo: passwordHistoryRepo,
		trustedDeviceRepo:   trustedDeviceRepo,
		roleRepo:            roleRepo,
		membershipRoleRepo:  membershipRoleRepo,
		riskService:         riskService,
		pwnedValidator:      pwnedValidator,
		auditService:        auditService,
		hasher:              hasher,
		rateLimiter:         rateLimiter,
		sessionCache:        sessionCache,
		jwtConfig:           jwtConfig,
		logger:              logger,
	}
}

func (s *AuthServiceImpl) Register(ctx context.Context, req *model.RegisterRequest, ip, userAgent string) (*model.RegisterResponse, error) {
	if errs := validator.ValidateRegisterRequest(req); len(errs) > 0 {
		return nil, fmt.Errorf("validation failed: %v", errs)
	}

	email := strings.ToLower(norm.NFKC.String(req.Email))

	tx, err := s.db.Begin(ctx)
	if err != nil {
		fmt.Printf("DEBUG: Register Begin Error: %v\n", err)
		return nil, fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil && !strings.Contains(err.Error(), "no rows") {
		fmt.Printf("DEBUG: Register FindByEmail Error: %v\n", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("email already registered")
	}

	// Create Tenant
	tenant := &model.Tenant{
		Name:     req.Username + "'s Organization",
		Slug:     req.TenantSlug,
		IsActive: true,
		Settings: make(map[string]interface{}),
	}
	if err := s.tenantRepo.Create(ctx, tx, tenant); err != nil {
		return nil, err
	}

	// Create User
	// Compromised Password Check
	if pwned, _, _ := s.pwnedValidator.IsPwned(ctx, req.Password); pwned {
		return nil, fmt.Errorf("this password has been found in a data breach, please use a more secure password")
	}

	hash, salt, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, err
	}
	user := &model.User{
		Email:      email,
		Username:   req.Username,
		Phone:      nil,
		IsActive:   true,
		IsVerified: false,
		Metadata:   make(map[string]interface{}),
	}
	if err := s.userRepo.Create(ctx, tx, user); err != nil {
		return nil, err
	}

	// Create Credentials
	cred := &model.UserCredential{UserID: user.ID, PasswordHash: hash, PasswordSalt: salt, PasswordAlgo: "argon2id"}
	if err := s.credRepo.Create(ctx, tx, cred); err != nil {
		return nil, err
	}

	// Record password history
	if err := s.passwordHistoryRepo.Create(ctx, tx, user.ID, hash, salt); err != nil {
		return nil, err
	}

	// Create Membership
	membership := &model.TenantMembership{UserID: user.ID, TenantID: tenant.ID, Status: "active"}
	if err := s.membershipRepo.Create(ctx, tx, membership); err != nil {
		return nil, err
	}

	// Assign Admin Role
	role, err := s.roleRepo.FindByName(ctx, nil, "admin")
	if err != nil {
		return nil, fmt.Errorf("error finding admin role: %w", err)
	}
	if role == nil {
		return nil, fmt.Errorf("system role 'admin' not found - please run migrations to seed roles")
	}
	if err := s.membershipRoleRepo.AddRole(ctx, tx, membership.ID, role.ID); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("error committing transaction: %w", err)
	}

	// Generate Email Verification Token
	token, _ := security.GenerateSecureToken(32)
	tokenHash := security.HashToken(token)
	st := &model.SecurityToken{
		UserID:    user.ID,
		TokenType: "email_verification",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		IPAddress: ip,
		UserAgent: userAgent,
		Metadata:  make(map[string]interface{}),
	}
	if err := s.tokenRepo.Create(ctx, st); err != nil {
		s.logger.Error("failed to create verification token", "error", err, "email", email)
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}
	if os.Getenv("MFA_TEST_MODE") == "true" {
		s.logger.Info("email verification token generated", "email", email, "token", token, "token_hash", tokenHash)
	}

	s.auditService.Log(ctx, "user.registered", &user.ID, &tenant.ID, "user", &user.ID, nil, user, ip, userAgent)

	return &model.RegisterResponse{Message: "Registration successful. Please verify your email."}, nil
}

func (s *AuthServiceImpl) VerifyEmail(ctx context.Context, rawToken string, ip, userAgent string) error {
	tokenHash := security.HashToken(rawToken)
	token, err := s.tokenRepo.FindValidToken(ctx, tokenHash, "email_verification")
	if err != nil || token == nil {
		s.logger.Warn("verification token not found or invalid", "token_hash", tokenHash, "error", err)
		return fmt.Errorf("invalid or expired verification token")
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.userRepo.SetVerified(ctx, tx, token.UserID); err != nil {
		return err
	}
	if err := s.tokenRepo.MarkUsed(ctx, tx, token.ID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	membership, _ := s.membershipRepo.FindActiveByUserID(ctx, token.UserID)
	var tid *string
	if membership != nil {
		tid = &membership.TenantID
	}
	s.auditService.Log(ctx, "user.email_verified", &token.UserID, tid, "user", &token.UserID, map[string]bool{"is_verified": false}, map[string]bool{"is_verified": true}, ip, userAgent)
	return nil
}

func (s *AuthServiceImpl) Login(ctx context.Context, req *model.LoginRequest, ip, userAgent string) (*model.LoginResponse, error) {
	// Rate limit login attempts per IP and per Email
	maxIPAttempts := 10
	if os.Getenv("MFA_TEST_MODE") == "true" {
		maxIPAttempts = 200
	}
	limitRet, err := s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      "login_ip:" + ip,
		MaxCount: maxIPAttempts,
		Window:   1 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	if !limitRet.Allowed {
		return nil, fmt.Errorf("too many attempts from this IP, try again later")
	}

	maxEmailAttempts := 5
	if os.Getenv("MFA_TEST_MODE") == "true" {
		maxEmailAttempts = 100
	}
	limitRet, err = s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      "login_email:" + req.Email,
		MaxCount: maxEmailAttempts,
		Window:   5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	if !limitRet.Allowed {
		return nil, fmt.Errorf("too many attempts for this email, try again later")
	}

	// 1. Find User
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		// Timing attack protection: dummy hashing
		dummyHash := "0000000000000000000000000000000000000000000000000000000000000000"
		dummySalt := "00000000000000000000000000000000"
		s.hasher.Verify(req.Password, dummyHash, dummySalt)
		return nil, fmt.Errorf("invalid email or password")
	}

	if user.IsSuspended {
		return nil, fmt.Errorf("account has been suspended")
	}
	if !user.IsVerified {
		return nil, fmt.Errorf("please verify your email")
	}

	// 2. Find Credentials
	cred, err := s.credRepo.FindByUserID(ctx, user.ID)
	if err != nil || cred == nil {
		return nil, fmt.Errorf("invalid email or password")
	}

	// 3. Verify Password
	match, err := s.hasher.Verify(req.Password, cred.PasswordHash, cred.PasswordSalt)
	if err != nil || !match {
		count, _ := s.userRepo.IncrementFailedLogin(ctx, user.ID)

		if count >= 5 {
			s.userRepo.Suspend(ctx, user.ID)
			s.eventRepo.Create(ctx, &model.SecurityEvent{
				UserID:    &user.ID,
				EventType: "auth.account_suspended",
				Severity:  "critical",
				Details:   "Max failed login attempts reached",
				IPAddress: ip,
				UserAgent: userAgent,
			})
		}

		return nil, fmt.Errorf("invalid email or password")
	}

	// 4. Reset Failed Logins
	s.userRepo.UpdateLastLogin(ctx, user.ID, ip)

	membership, _ := s.membershipRepo.FindActiveByUserID(ctx, user.ID)
	var tenantID *string
	var membershipID *string
	if membership != nil {
		tenantID = &membership.TenantID
		membershipID = &membership.ID
	}

	// 4. Adaptive Security (Risk Analysis)
	risk, err := s.riskService.AnalyzeLoginRisk(ctx, user.ID, ip, req.DeviceFingerprint)
	if err != nil {
		s.logger.Error("risk analysis failed", "error", err, "user_id", user.ID)
	}

	mfa, err := s.mfaRepo.FindPrimaryActive(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if mfa != nil {
		isTrusted := false
		if req.DeviceFingerprint != "" {
			td, err := s.trustedDeviceRepo.FindByUserAndFingerprint(ctx, user.ID, req.DeviceFingerprint)
			if err == nil && td != nil {
				// Even if trusted, if risk is High, we force MFA (Adaptive Step-up)
				if risk == nil || risk.Level != model.RiskHigh {
					isTrusted = true
				} else {
					s.logger.Warn("adaptive step-up: high risk login from trusted device", "user_id", user.ID, "reasons", risk.Reasons)
				}
			}
		}

		if !isTrusted {
			mfaToken, _ := security.GenerateMFAToken(s.jwtConfig, user.ID, 5*time.Minute)
			return &model.LoginResponse{MFARequired: true, MFAToken: mfaToken}, nil
		}
	} else if risk != nil && risk.Level == model.RiskHigh {
		// No MFA enrolled, but risk is High. Block or require extra verification?
		// For a "World-Class" system, we might block or trigger an email verification.
		// For now, let's just log a critical event.
		s.eventRepo.Create(ctx, &model.SecurityEvent{
			UserID:    &user.ID,
			EventType: "auth.high_risk_login_no_mfa",
			Severity:  "critical",
			Details:   fmt.Sprintf("High risk login from %s. Reasons: %v", ip, risk.Reasons),
			IPAddress: ip,
			UserAgent: userAgent,
		})
	}

	// 7. Session & Tokens
	sessionToken, _ := security.GenerateSecureToken(32)
	sessionHash := security.HashToken(sessionToken)
	refreshToken, _ := security.GenerateSecureToken(32)
	refreshHash := security.HashToken(refreshToken)
	familyID, _ := security.GenerateSecureToken(16)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	session := &model.Session{
		UserID: user.ID, TenantID: tenantID, MembershipID: membershipID, TokenHash: sessionHash,
		IPAddress: ip, UserAgent: userAgent, DeviceFingerprint: req.DeviceFingerprint,
		DeviceName:  req.DeviceName,
		MFAVerified: true, ExpiresAt: time.Now().Add(24 * time.Hour), IdleTimeoutAt: time.Now().Add(30 * time.Minute),
	}
	if err := s.sessionRepo.Create(ctx, tx, session); err != nil {
		return nil, err
	}

	rf := &model.RefreshToken{
		SessionID: session.ID, UserID: user.ID, TokenHash: refreshHash, FamilyID: familyID,
		Generation: 1, IPAddress: ip, DeviceFingerprint: req.DeviceFingerprint,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := s.refreshTokenRepo.Create(ctx, tx, rf); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	// Cache session
	sessionCacheTenantID := ""
	if session.TenantID != nil {
		sessionCacheTenantID = *session.TenantID
	}
	s.sessionCache.Set(ctx, session.ID, &redis.CachedSession{
		SessionID:         session.ID,
		UserID:            session.UserID,
		TenantID:          sessionCacheTenantID,
		TokenHash:         session.TokenHash,
		DeviceFingerprint: session.DeviceFingerprint,
		MFAVerified:       session.MFAVerified,
		ExpiresAt:         session.ExpiresAt,
		IdleTimeoutAt:     session.IdleTimeoutAt,
	})

	s.auditService.Log(ctx, "auth.login_success", &user.ID, session.TenantID, "session", &session.ID, nil, session, ip, userAgent)

	tid := ""
	if session.TenantID != nil {
		tid = *session.TenantID
	}
	accessToken, _ := security.GenerateAccessToken(s.jwtConfig, security.JWTClaims{
		Sub: user.ID,
		Sid: session.ID,
		Tid: tid,
	})

	return &model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, req *model.RefreshTokenRequest, ip, userAgent string) (*model.LoginResponse, error) {
	refreshHash := security.HashToken(req.RefreshToken)
	token, err := s.refreshTokenRepo.FindByTokenHash(ctx, refreshHash)
	if err != nil || token == nil || token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	if token.DeviceFingerprint != "" && token.DeviceFingerprint != req.DeviceFingerprint {
		return nil, fmt.Errorf("mismatched device fingerprint for refresh token")
	}

	session, err := s.sessionRepo.FindByID(ctx, token.SessionID)
	if err != nil || session == nil {
		return nil, fmt.Errorf("invalid session")
	}

	if token.UsedAt != nil {
		// Reuse detection: revoke all in family
		tx, err := s.db.Begin(ctx)
		if err == nil {
			s.refreshTokenRepo.RevokeByFamily(ctx, tx, token.FamilyID)
			s.sessionRepo.RevokeByID(ctx, token.SessionID, "refresh_token_reuse", "system")
			tx.Commit(ctx)
		}
		s.eventRepo.Create(ctx, &model.SecurityEvent{UserID: &token.UserID, EventType: "auth.refresh_reuse", Severity: "critical", Details: "suspicious activity", IPAddress: ip, UserAgent: userAgent})
		return nil, fmt.Errorf("refresh token reuse detected: suspicious activity")
	}

	if session.DeviceFingerprint != "" && session.DeviceFingerprint != req.DeviceFingerprint {
		return nil, fmt.Errorf("mismatched device fingerprint: suspicious activity")
	}

	// New Tokens
	newSessionToken, _ := security.GenerateSecureToken(32)
	newSessionHash := security.HashToken(newSessionToken)
	newRefreshToken, _ := security.GenerateSecureToken(32)
	newRefreshHash := security.HashToken(newRefreshToken)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// TOCTOU: Check session again inside transaction
	session, err = s.sessionRepo.FindByID(ctx, token.SessionID)
	if err != nil || session == nil || session.RevokedAt != nil {
		return nil, fmt.Errorf("session revoked")
	}

	// Update Session
	if err := s.sessionRepo.UpdateTokenHash(ctx, tx, session.ID, newSessionHash); err != nil {
		return nil, err
	}

	// Rotate Refresh Token
	if err := s.refreshTokenRepo.MarkUsed(ctx, tx, token.ID); err != nil {
		return nil, err
	}
	newRf := &model.RefreshToken{
		SessionID: session.ID, UserID: token.UserID, TokenHash: newRefreshHash, FamilyID: token.FamilyID,
		Generation: token.Generation + 1, ParentTokenID: &token.ID,
		IPAddress: ip, DeviceFingerprint: req.DeviceFingerprint,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}
	if err := s.refreshTokenRepo.Create(ctx, tx, newRf); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	var tid string
	if session.TenantID != nil {
		tid = *session.TenantID
	}
	newAccessToken, _ := security.GenerateAccessToken(s.jwtConfig, security.JWTClaims{
		Sub: token.UserID,
		Sid: session.ID,
		Tid: tid,
	})

	return &model.LoginResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (s *AuthServiceImpl) Logout(ctx context.Context, sessionID, userID, tokenHash string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.sessionRepo.RevokeByID(ctx, sessionID, "logout", userID); err != nil {
		return err
	}
	if err := s.refreshTokenRepo.RevokeBySessionID(ctx, tx, sessionID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	return s.sessionCache.Delete(ctx, userID, sessionID)
}

func (s *AuthServiceImpl) LogoutAll(ctx context.Context, userID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.sessionRepo.RevokeAllByUser(ctx, tx, userID, "logout_all"); err != nil {
		return err
	}
	if err := s.refreshTokenRepo.RevokeAllByUser(ctx, tx, userID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	return s.sessionCache.DeleteByUserID(ctx, userID)
}

func (s *AuthServiceImpl) ValidateSession(ctx context.Context, sessionID string) (*model.Session, error) {
	return s.sessionRepo.FindByID(ctx, sessionID)
}

func (s *AuthServiceImpl) ForgotPassword(ctx context.Context, email string, ip, userAgent string) error {
	// Rate limit
	limitRet, err := s.rateLimiter.Check(ctx, redis.RateLimitConfig{
		Key:      fmt.Sprintf("password_reset_lock:%s", email),
		MaxCount: 5,
		Window:   1 * time.Hour,
	})
	if err != nil {
		return err
	}
	if !limitRet.Allowed {
		return nil // Anti-enumeration: don't return error
	}

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil
		}
		return err
	}
	if user == nil {
		return nil // Timing attack protection
	}

	token, _ := security.GenerateSecureToken(32)
	tokenHash := security.HashToken(token)
	st := &model.SecurityToken{
		UserID:    user.ID,
		TokenType: "password_reset",
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IPAddress: ip,
		UserAgent: userAgent,
		Metadata:  make(map[string]interface{}),
	}
	if err := s.tokenRepo.Create(ctx, st); err != nil {
		s.logger.Error("failed to create password reset token", "error", err, "email", email)
		return err
	}
	if os.Getenv("MFA_TEST_MODE") == "true" {
		s.logger.Info("password reset token generated", "email", email, "token", token, "token_hash", tokenHash)
	}

	membership, _ := s.membershipRepo.FindActiveByUserID(ctx, user.ID)
	var tid *string
	if membership != nil {
		tid = &membership.TenantID
	}
	s.auditService.Log(ctx, "auth.password_reset_requested", &user.ID, tid, "user", &user.ID, nil, nil, ip, userAgent)
	return nil
}

func (s *AuthServiceImpl) ResetPassword(ctx context.Context, token, newPassword, ip, userAgent string) error {
	tokenHash := security.HashToken(token)
	st, err := s.tokenRepo.FindValidToken(ctx, tokenHash, "password_reset")
	if err != nil || st == nil {
		return fmt.Errorf("invalid or expired token")
	}

	if err := validator.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Compromised Password Check
	if pwned, _, _ := s.pwnedValidator.IsPwned(ctx, newPassword); pwned {
		return fmt.Errorf("this password has been found in a data breach, please use a more secure password")
	}

	recent, err := s.passwordHistoryRepo.GetRecentPasswords(ctx, st.UserID, 5)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to get password history", "error", err)
	}
	for _, h := range recent {
		match, _ := s.hasher.Verify(newPassword, h.PasswordHash, h.PasswordSalt)
		if match {
			return fmt.Errorf("password has been recently used")
		}
	}

	hash, salt, err := s.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.credRepo.UpdatePassword(ctx, tx, st.UserID, hash, salt); err != nil {
		return err
	}

	if err := s.userRepo.UpdatePasswordChangedAt(ctx, tx, st.UserID); err != nil {
		return err
	}

	// Record password history
	if err := s.passwordHistoryRepo.Create(ctx, tx, st.UserID, hash, salt); err != nil {
		s.logger.ErrorContext(ctx, "failed to record password history", "error", err)
	}
	if err := s.passwordHistoryRepo.Cleanup(ctx, st.UserID, 5); err != nil {
		s.logger.ErrorContext(ctx, "failed to cleanup password history", "error", err)
	}

	if err := s.tokenRepo.MarkUsed(ctx, tx, st.ID); err != nil {
		return err
	}

	// Revoke all sessions on password change
	if err := s.sessionRepo.RevokeAllByUser(ctx, tx, st.UserID, "password_reset"); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	membership, _ := s.membershipRepo.FindActiveByUserID(ctx, st.UserID)
	var tid *string
	if membership != nil {
		tid = &membership.TenantID
	}
	s.auditService.Log(ctx, "user.password_reset_success", &st.UserID, tid, "user", &st.UserID, nil, nil, ip, userAgent)
	return nil
}
func (s *AuthServiceImpl) DeleteAccount(ctx context.Context, userID, ip, userAgent string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := s.userRepo.SoftDelete(ctx, userID); err != nil {
		return err
	}

	if err := s.sessionRepo.RevokeAllByUser(ctx, tx, userID, "account_deleted"); err != nil {
		return err
	}

	if err := s.refreshTokenRepo.RevokeAllByUser(ctx, tx, userID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	membership, _ := s.membershipRepo.FindActiveByUserID(ctx, userID)
	var tid *string
	if membership != nil {
		tid = &membership.TenantID
	}
	s.auditService.Log(ctx, "auth.account_deleted", &userID, tid, "user", &userID, nil, nil, ip, userAgent)
	return s.sessionCache.DeleteByUserID(ctx, userID)
}
