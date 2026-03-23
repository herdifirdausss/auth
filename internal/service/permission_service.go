package service

import (
	"context"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=service
type PermissionService interface {
	HasPermission(ctx context.Context, userID, tenantID, required string) (bool, error)
	GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error)
	GetUserRoles(ctx context.Context, membershipID string) ([]model.Role, error)
}

type DefaultPermissionService struct {
	roleRepo repository.RoleRepository
}

func NewDefaultPermissionService(roleRepo repository.RoleRepository) *DefaultPermissionService {
	return &DefaultPermissionService{
		roleRepo: roleRepo,
	}
}

func (s *DefaultPermissionService) HasPermission(ctx context.Context, userID, tenantID, required string) (bool, error) {
	perms, err := s.roleRepo.FindPermissionsByUserAndTenant(ctx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("error getting permissions: %w", err)
	}
	return security.MatchPermission(perms, required), nil
}

func (s *DefaultPermissionService) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	return s.roleRepo.FindPermissionsByUserAndTenant(ctx, userID, tenantID)
}

func (s *DefaultPermissionService) GetUserRoles(ctx context.Context, membershipID string) ([]model.Role, error) {
	return s.roleRepo.FindRolesByMembership(ctx, membershipID)
}
