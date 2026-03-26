package service

//go:generate mockgen -source=admin_service.go -destination=../mocks/mock_admin_service.go -package=mocks

import (
	"context"
	"log/slog"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
)

type AdminService interface {
	ListTenants(ctx context.Context) ([]*model.Tenant, error)
	UpdateTenantStatus(ctx context.Context, tenantID string, isActive bool) error
}

type AdminServiceImpl struct {
	tenantRepo repository.TenantRepository
	logger     *slog.Logger
}

func NewAdminService(tenantRepo repository.TenantRepository, logger *slog.Logger) *AdminServiceImpl {
	return &AdminServiceImpl{
		tenantRepo: tenantRepo,
		logger:     logger,
	}
}

func (s *AdminServiceImpl) ListTenants(ctx context.Context) ([]*model.Tenant, error) {
	// For simplicity, we'll assume a GetAll method exists or we use a more complex query
	// Since we are hardening, let's implement List in TenantRepository first if needed.
	return s.tenantRepo.List(ctx)
}

func (s *AdminServiceImpl) UpdateTenantStatus(ctx context.Context, tenantID string, isActive bool) error {
	return s.tenantRepo.UpdateStatus(ctx, tenantID, isActive)
}
