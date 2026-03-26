package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
)

//go:generate mockgen -source=tenant_service.go -destination=../mocks/mock_tenant_service.go -package=mocks
type TenantService interface {
	InviteMember(ctx context.Context, inviterID, email, tenantID string) error
	AcceptInvitation(ctx context.Context, userID, tenantID string) error
	UpdateSettings(ctx context.Context, tenantID string, settings map[string]interface{}) error
	UpdateStatus(ctx context.Context, tenantID string, isActive bool) error
}

type TenantServiceImpl struct {
	db             repository.Transactor
	userRepo       repository.UserRepository
	membershipRepo repository.TenantMembershipRepository
	tenantRepo     repository.TenantRepository
	roleRepo       repository.RoleRepository
	logger         *slog.Logger
}

func NewTenantService(
	db repository.Transactor,
	userRepo repository.UserRepository,
	membershipRepo repository.TenantMembershipRepository,
	tenantRepo repository.TenantRepository,
	roleRepo repository.RoleRepository,
	logger *slog.Logger,
) *TenantServiceImpl {
	return &TenantServiceImpl{
		db:             db,
		userRepo:       userRepo,
		membershipRepo: membershipRepo,
		tenantRepo:     tenantRepo,
		roleRepo:       roleRepo,
		logger:         logger,
	}
}

func (s *TenantServiceImpl) InviteMember(ctx context.Context, inviterID, email, tenantID string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return err
	}

	if user == nil {
		user = &model.User{
			Email:    email,
			Username: email,
			IsActive: true,
			Metadata: make(map[string]interface{}),
		}
		if err := s.userRepo.Create(ctx, nil, user); err != nil {
			return err
		}
	}

	existing, err := s.membershipRepo.FindByUserAndTenant(ctx, user.ID, tenantID)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("user is already a member or invited to this tenant")
	}

	membership := &model.TenantMembership{
		UserID:    user.ID,
		TenantID:  tenantID,
		Status:    "invited",
		InvitedBy: &inviterID,
	}

	return s.membershipRepo.Create(ctx, nil, membership)
}

func (s *TenantServiceImpl) AcceptInvitation(ctx context.Context, userID, tenantID string) error {
	membership, err := s.membershipRepo.FindByUserAndTenant(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	if membership == nil {
		return fmt.Errorf("invitation not found")
	}
	if membership.Status != "invited" {
		return fmt.Errorf("membership is not in invited status")
	}

	now := time.Now()
	return s.membershipRepo.UpdateStatus(ctx, nil, membership.ID, "active", &now)
}

func (s *TenantServiceImpl) UpdateSettings(ctx context.Context, tenantID string, settings map[string]interface{}) error {
	return s.tenantRepo.UpdateSettings(ctx, tenantID, settings)
}

func (s *TenantServiceImpl) UpdateStatus(ctx context.Context, tenantID string, isActive bool) error {
	return s.tenantRepo.UpdateStatus(ctx, tenantID, isActive)
}
