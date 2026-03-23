package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/validator"
)

type AuthService interface {
	Register(ctx context.Context, req *model.RegisterRequest, ipAddress, userAgent string) (*model.RegisterResponse, error)
}

type AuthServiceImpl struct {
	db              *sql.DB
	userRepo        repository.UserRepository
	credRepo        repository.CredentialRepository
	tokenRepo       repository.SecurityTokenRepository
	eventRepo       repository.SecurityEventRepository
	tenantRepo      repository.TenantRepository
	membershipRepo  repository.TenantMembershipRepository
	hasher          security.PasswordHasher
}

func NewAuthService(
	db *sql.DB,
	userRepo repository.UserRepository,
	credRepo repository.CredentialRepository,
	tokenRepo repository.SecurityTokenRepository,
	eventRepo repository.SecurityEventRepository,
	tenantRepo repository.TenantRepository,
	membershipRepo repository.TenantMembershipRepository,
	hasher security.PasswordHasher,
) *AuthServiceImpl {
	return &AuthServiceImpl{
		db:             db,
		userRepo:       userRepo,
		credRepo:       credRepo,
		tokenRepo:      tokenRepo,
		eventRepo:      eventRepo,
		tenantRepo:     tenantRepo,
		membershipRepo: membershipRepo,
		hasher:         hasher,
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
