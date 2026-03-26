package service

import (
	"context"
	"fmt"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
)

//go:generate mockgen -source=permission_service.go -destination=../mocks/mock_permission_service.go -package=mocks
type PermissionService interface {
	HasPermission(ctx context.Context, userID, tenantID, required string) (bool, error)
	GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error)
	GetUserRoles(ctx context.Context, membershipID string) ([]model.Role, error)
	HasRole(ctx context.Context, userID, tenantID, roleName string) (bool, error)
}

type DefaultPermissionService struct {
	roleRepo repository.RoleRepository
	cache    redis.PermissionCache
}

func NewDefaultPermissionService(roleRepo repository.RoleRepository, cache redis.PermissionCache) *DefaultPermissionService {
	return &DefaultPermissionService{
		roleRepo: roleRepo,
		cache:    cache,
	}
}

func (s *DefaultPermissionService) HasPermission(ctx context.Context, userID, tenantID, required string) (bool, error) {
	perms, err := s.GetUserPermissions(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	return security.MatchPermission(perms, required), nil
}

func (s *DefaultPermissionService) GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	var perms []string
	var err error

	if s.cache != nil {
		perms, err = s.cache.GetPermissions(ctx, tenantID, userID)
	}

	if err != nil || perms == nil {
		perms, err = s.roleRepo.FindPermissionsByUserAndTenant(ctx, userID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("error getting permissions: %w", err)
		}
		if s.cache != nil {
			_ = s.cache.SetPermissions(ctx, tenantID, userID, perms)
		}
	}
	return perms, nil
}

func (s *DefaultPermissionService) GetUserRoles(ctx context.Context, membershipID string) ([]model.Role, error) {
	// For membership-specific roles, we could also cache by membershipID
	// But let's stick to user-tenant for now to keep it simple.
	return s.roleRepo.FindRolesByMembership(ctx, membershipID)
}

func (s *DefaultPermissionService) HasRole(ctx context.Context, userID, tenantID, roleName string) (bool, error) {
	var roles []model.Role
	var err error

	if s.cache != nil {
		roles, err = s.cache.GetRoles(ctx, tenantID, userID)
	}

	if err != nil || roles == nil {
		roles, err = s.roleRepo.FindRolesByUserAndTenant(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		if s.cache != nil {
			_ = s.cache.SetRoles(ctx, tenantID, userID, roles)
		}
	}

	for _, r := range roles {
		if r.Name == roleName {
			return true, nil
		}
	}
	return false, nil
}
