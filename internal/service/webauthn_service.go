package service

//go:generate mockgen -source=webauthn_service.go -destination=../mocks/mock_webauthn_service.go -package=mocks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/utils"
)

type WebAuthnService interface {
	BeginRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error)
	FinishRegistration(ctx context.Context, userID string, responseBody []byte) error
	BeginLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, error)
	FinishLogin(ctx context.Context, loginSessionID string, responseBody []byte) (*model.LoginResponse, error)
}

type WebAuthnServiceImpl struct {
	web           *webauthn.WebAuthn
	userRepo      repository.UserRepository
	mfaRepo       repository.MFARepository
	sessRepo      repository.SessionRepository
	rfRepo        repository.RefreshTokenRepository
	membershipRepo repository.TenantMembershipRepository
	jwtConfig     security.JWTConfig
	rateLimiter   redis.RateLimiter
	sessionCache  redis.SessionCache
	clock         utils.Clock
	logger        *slog.Logger
}

func NewWebAuthnService(
	userRepo repository.UserRepository,
	mfaRepo repository.MFARepository,
	sessRepo repository.SessionRepository,
	rfRepo repository.RefreshTokenRepository,
	membershipRepo repository.TenantMembershipRepository,
	jwtConfig security.JWTConfig,
	rateLimiter redis.RateLimiter,
	sessionCache redis.SessionCache,
	clock utils.Clock,
	logger *slog.Logger,
) (*WebAuthnServiceImpl, error) {
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Auth Service",
		RPID:          os.Getenv("WEBAUTHN_RP_ID"), // e.g. "localhost"
		RPOrigins:     []string{os.Getenv("WEBAUTHN_RP_ORIGIN")}, // e.g. "http://localhost:3000"
	})
	if err != nil {
		return nil, err
	}

	return &WebAuthnServiceImpl{
		web:           w,
		userRepo:      userRepo,
		mfaRepo:       mfaRepo,
		sessRepo:      sessRepo,
		rfRepo:        rfRepo,
		membershipRepo: membershipRepo,
		jwtConfig:     jwtConfig,
		rateLimiter:   rateLimiter,
		sessionCache:  sessionCache,
		clock:         clock,
		logger:        logger,
	}, nil
}

// User Wrapper to satisfy webauthn.User interface
type webauthnUser struct {
	user        *model.User
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *webauthnUser) WebAuthnName() string {
	return u.user.Email
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.user.Username
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (s *WebAuthnServiceImpl) getWebauthnUser(ctx context.Context, userID string) (*webauthnUser, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	methods, err := s.mfaRepo.FindAllByUserIDAndType(ctx, userID, "webauthn")
	if err != nil {
		return nil, err
	}

	var credentials []webauthn.Credential
	for _, m := range methods {
		var cred webauthn.Credential
		if err := json.Unmarshal([]byte(m.SecretEncrypted), &cred); err != nil {
			s.logger.ErrorContext(ctx, "failed to unmarshal webauthn credential", "error", err, "id", m.ID)
			continue
		}
		credentials = append(credentials, cred)
	}
	
	return &webauthnUser{
		user:        user,
		credentials: credentials,
	}, nil
}

func (s *WebAuthnServiceImpl) BeginRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error) {
	wUser, err := s.getWebauthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	options, sessionData, err := s.web.BeginRegistration(wUser)
	if err != nil {
		return nil, err
	}

	// Store sessionData in Redis for 5 minutes
	data, _ := json.Marshal(sessionData)
	err = s.sessionCache.SetRaw(ctx, "webauthn_reg:"+userID, string(data), 5*time.Minute)
	if err != nil {
		return nil, err
	}

	return options, nil
}

func (s *WebAuthnServiceImpl) FinishRegistration(ctx context.Context, userID string, responseBody []byte) error {
	wUser, err := s.getWebauthnUser(ctx, userID)
	if err != nil {
		return err
	}

	cached, err := s.sessionCache.GetRaw(ctx, "webauthn_reg:"+userID)
	if err != nil {
		return fmt.Errorf("registration session expired or not found")
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(cached), &sessionData); err != nil {
		return err
	}

	// Use protocol level parsing to avoid http.Request dependency
	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(responseBody)
	if err != nil {
		return fmt.Errorf("failed to parse credential response: %w", err)
	}

	credential, err := s.web.CreateCredential(wUser, sessionData, parsedResponse)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	credBytes, _ := json.Marshal(credential)
	method := &model.MFAMethod{
		UserID:          userID,
		MethodType:      "webauthn",
		MethodName:      utils.Ptr("Security Key"),
		SecretEncrypted: string(credBytes),
		CredentialID:    utils.Ptr(string(credential.ID)),
		PublicKey:       utils.Ptr(string(credential.PublicKey)),
		IsActive:        true,
		IsPrimary:       true,
	}

	return s.mfaRepo.Create(ctx, method)
}

func (s *WebAuthnServiceImpl) BeginLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	wUser, err := s.getWebauthnUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	options, sessionData, err := s.web.BeginLogin(wUser)
	if err != nil {
		return nil, err
	}

	// Store sessionData in Redis (use a different prefix or key structure)
	// We'll use a temporary ID for the login session
	loginSessionID, _ := security.GenerateSecureToken(16)
	data, _ := json.Marshal(sessionData)
	err = s.sessionCache.SetRaw(ctx, "webauthn_login:"+loginSessionID, string(data), 5*time.Minute)
	if err != nil {
		return nil, err
	}

	return options, nil
}

func (s *WebAuthnServiceImpl) FinishLogin(ctx context.Context, loginSessionID string, responseBody []byte) (*model.LoginResponse, error) {
	cached, err := s.sessionCache.GetRaw(ctx, "webauthn_login:"+loginSessionID)
	if err != nil {
		return nil, fmt.Errorf("login session expired or not found")
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(cached), &sessionData); err != nil {
		return nil, err
	}

	userID := string(sessionData.UserID)
	wUser, err := s.getWebauthnUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(responseBody)
	if err != nil {
		return nil, fmt.Errorf("failed to parse assertion response: %w", err)
	}

	credential, err := s.web.ValidateLogin(wUser, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to validate login: %w", err)
	}

	_ = credential // Could update counter here

	// Get User Tenant
	membership, err := s.membershipRepo.FindActiveByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if membership == nil {
		return nil, fmt.Errorf("user has no active tenant membership")
	}

	// Generate Session & Refresh Tokens
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
		MFAVerified:       true,
		ExpiresAt:         s.clock.Now().Add(7 * 24 * time.Hour),
		IdleTimeoutAt:     s.clock.Now().Add(30 * time.Minute),
	}

	_ = refreshHash
	_ = familyID

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
