package service

import (
	"context"
	"fmt"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
)

//go:generate mockgen -source=tenant_admin_service.go -destination=../mocks/mock_tenant_admin_service.go -package=mocks
type TenantAdminService interface {
	GetTenantConfig(ctx context.Context, tenantID string) (*model.Tenant, error)
	UpdateTenantConfig(ctx context.Context, tenantID string, settings map[string]interface{}, userID, ip, ua string) error

	ListRoles(ctx context.Context, tenantID string) ([]model.Role, error)
	CreateRole(ctx context.Context, tenantID string, role *model.Role, userID, ip, ua string) error
	UpdateRole(ctx context.Context, tenantID string, role *model.Role, userID, ip, ua string) error
	DeleteRole(ctx context.Context, tenantID string, roleID string, userID, ip, ua string) error

	ListMembers(ctx context.Context, tenantID string) ([]model.TenantMembership, error)
	UpdateMemberStatus(ctx context.Context, tenantID string, membershipID string, status string, userID, ip, ua string) error
	UpdateMemberRoles(ctx context.Context, tenantID string, membershipID string, roleIDs []string, userID, ip, ua string) error
	RemoveMember(ctx context.Context, tenantID string, membershipID string, userID, ip, ua string) error
}

type tenantAdminService struct {
	db             repository.Pool
	tenantRepo     repository.TenantRepository
	membershipRepo repository.TenantMembershipRepository
	roleRepo       repository.RoleRepository
	memRoleRepo    repository.MembershipRoleRepository
	auditService   AuditService
}

func NewTenantAdminService(
	db repository.Pool,
	tenantRepo repository.TenantRepository,
	membershipRepo repository.TenantMembershipRepository,
	roleRepo repository.RoleRepository,
	memRoleRepo repository.MembershipRoleRepository,
	auditService AuditService,
) TenantAdminService {
	return &tenantAdminService{
		db:             db,
		tenantRepo:     tenantRepo,
		membershipRepo: membershipRepo,
		roleRepo:       roleRepo,
		memRoleRepo:    memRoleRepo,
		auditService:   auditService,
	}
}

func (s *tenantAdminService) GetTenantConfig(ctx context.Context, tenantID string) (*model.Tenant, error) {
	return s.tenantRepo.FindByID(ctx, tenantID)
}

func (s *tenantAdminService) UpdateTenantConfig(ctx context.Context, tenantID string, settings map[string]interface{}, userID, ip, ua string) error {
	oldTenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if oldTenant == nil {
		return fmt.Errorf("tenant not found")
	}

	if err := s.tenantRepo.UpdateSettings(ctx, tenantID, settings); err != nil {
		return err
	}

	s.auditService.Log(ctx, "tenant.settings_updated", &userID, &tenantID, "tenant", &tenantID, oldTenant.Settings, settings, ip, ua)
	return nil
}

func (s *tenantAdminService) ListRoles(ctx context.Context, tenantID string) ([]model.Role, error) {
	return s.roleRepo.ListByTenant(ctx, tenantID)
}

func (s *tenantAdminService) CreateRole(ctx context.Context, tenantID string, role *model.Role, userID, ip, ua string) error {
	role.TenantID = &tenantID
	role.IsSystem = false
	if err := s.roleRepo.Create(ctx, role); err != nil {
		return err
	}

	s.auditService.Log(ctx, "role.created", &userID, &tenantID, "role", &role.ID, nil, role, ip, ua)
	return nil
}

func (s *tenantAdminService) UpdateRole(ctx context.Context, tenantID string, role *model.Role, userID, ip, ua string) error {
	oldRole, err := s.roleRepo.FindByID(ctx, role.ID)
	if err != nil {
		return err
	}
	if oldRole == nil || oldRole.TenantID == nil || *oldRole.TenantID != tenantID {
		return fmt.Errorf("role not found or access denied")
	}
	if oldRole.IsSystem {
		return fmt.Errorf("cannot update system roles")
	}

	if err := s.roleRepo.Update(ctx, role); err != nil {
		return err
	}

	s.auditService.Log(ctx, "role.updated", &userID, &tenantID, "role", &role.ID, oldRole, role, ip, ua)
	return nil
}

func (s *tenantAdminService) DeleteRole(ctx context.Context, tenantID string, roleID string, userID, ip, ua string) error {
	role, err := s.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil || role.TenantID == nil || *role.TenantID != tenantID {
		return fmt.Errorf("role not found or access denied")
	}
	if role.IsSystem {
		return fmt.Errorf("cannot delete system roles")
	}

	if err := s.roleRepo.Delete(ctx, roleID); err != nil {
		return err
	}

	s.auditService.Log(ctx, "role.deleted", &userID, &tenantID, "role", &roleID, role, nil, ip, ua)
	return nil
}

func (s *tenantAdminService) ListMembers(ctx context.Context, tenantID string) ([]model.TenantMembership, error) {
	return s.membershipRepo.ListByTenant(ctx, tenantID)
}

func (s *tenantAdminService) UpdateMemberStatus(ctx context.Context, tenantID string, membershipID string, status string, userID, ip, ua string) error {
	m, err := s.membershipRepo.FindByID(ctx, membershipID)
	if err != nil {
		return err
	}
	if m == nil || m.TenantID != tenantID {
		return fmt.Errorf("membership not found or access denied")
	}

	var acceptedAt *time.Time
	if status == "active" && m.Status == "invited" {
		now := time.Now()
		acceptedAt = &now
	}

	if err := s.membershipRepo.UpdateStatus(ctx, nil, membershipID, status, acceptedAt); err != nil {
		return err
	}

	s.auditService.Log(ctx, "membership.status_updated", &userID, &tenantID, "membership", &membershipID, m.Status, status, ip, ua)
	return nil
}

func (s *tenantAdminService) UpdateMemberRoles(ctx context.Context, tenantID string, membershipID string, roleIDs []string, userID, ip, ua string) error {
	m, err := s.membershipRepo.FindByID(ctx, membershipID)
	if err != nil {
		return err
	}
	if m == nil || m.TenantID != tenantID {
		return fmt.Errorf("membership not found or access denied")
	}

	// Verify all roles belong to the tenant or are system roles
	for _, rid := range roleIDs {
		r, err := s.roleRepo.FindByID(ctx, rid)
		if err != nil {
			return err
		}
		if r == nil {
			return fmt.Errorf("role %s not found", rid)
		}
		if !r.IsSystem && (r.TenantID == nil || *r.TenantID != tenantID) {
			return fmt.Errorf("role %s access denied", rid)
		}
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	oldRoles, _ := s.roleRepo.FindRolesByMembership(ctx, membershipID)

	if err := s.memRoleRepo.RemoveAllRoles(ctx, tx, membershipID); err != nil {
		return err
	}

	for _, rid := range roleIDs {
		if err := s.memRoleRepo.AddRole(ctx, tx, membershipID, rid); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.auditService.Log(ctx, "membership.roles_updated", &userID, &tenantID, "membership", &membershipID, oldRoles, roleIDs, ip, ua)
	return nil
}

func (s *tenantAdminService) RemoveMember(ctx context.Context, tenantID string, membershipID string, userID, ip, ua string) error {
	m, err := s.membershipRepo.FindByID(ctx, membershipID)
	if err != nil {
		return err
	}
	if m == nil || m.TenantID != tenantID {
		return fmt.Errorf("membership not found or access denied")
	}

	if err := s.membershipRepo.Delete(ctx, nil, membershipID); err != nil {
		return err
	}

	s.auditService.Log(ctx, "membership.deleted", &userID, &tenantID, "membership", &membershipID, m, nil, ip, ua)
	return nil
}
