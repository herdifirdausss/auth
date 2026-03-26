package service

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAdminService_ListTenants(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tenantRepo := mocks.NewMockTenantRepository(ctrl)
	logger := slog.Default()
	s := NewAdminService(tenantRepo, logger)

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		tenants := []*model.Tenant{
			{ID: "t1", Name: "Tenant 1"},
			{ID: "t2", Name: "Tenant 2"},
		}
		tenantRepo.EXPECT().List(ctx).Return(tenants, nil)

		res, err := s.ListTenants(ctx)
		assert.NoError(t, err)
		assert.Equal(t, tenants, res)
	})

	t.Run("RepoError", func(t *testing.T) {
		tenantRepo.EXPECT().List(ctx).Return(nil, fmt.Errorf("db error"))

		res, err := s.ListTenants(ctx)
		assert.Error(t, err)
		assert.Nil(t, res)
	})
}

func TestAdminService_UpdateTenantStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tenantRepo := mocks.NewMockTenantRepository(ctrl)
	logger := slog.Default()
	s := NewAdminService(tenantRepo, logger)

	ctx := context.Background()
	tenantID := "t1"

	t.Run("Success", func(t *testing.T) {
		tenantRepo.EXPECT().UpdateStatus(ctx, tenantID, true).Return(nil)

		err := s.UpdateTenantStatus(ctx, tenantID, true)
		assert.NoError(t, err)
	})

	t.Run("RepoError", func(t *testing.T) {
		tenantRepo.EXPECT().UpdateStatus(ctx, tenantID, false).Return(fmt.Errorf("db error"))

		err := s.UpdateTenantStatus(ctx, tenantID, false)
		assert.Error(t, err)
	})
}
