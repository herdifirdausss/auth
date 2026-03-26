package service

import (
	"context"
	"errors"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestHasPermission_Allowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	mockRepo.EXPECT().FindPermissionsByUserAndTenant(ctx, "user1", "tenant1").Return([]string{"users:read"}, nil)

	allowed, err := svc.HasPermission(ctx, "user1", "tenant1", "users:read")
	assert.NoError(t, err)
	assert.True(t, allowed)
}

func TestHasPermission_Denied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	mockRepo.EXPECT().FindPermissionsByUserAndTenant(ctx, "user1", "tenant1").Return([]string{"users:read"}, nil)

	allowed, err := svc.HasPermission(ctx, "user1", "tenant1", "users:write")
	assert.NoError(t, err)
	assert.False(t, allowed)
}

func TestHasPermission_SuperAdmin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	mockRepo.EXPECT().FindPermissionsByUserAndTenant(ctx, "user1", "tenant1").Return([]string{"*"}, nil)

	allowed, err := svc.HasPermission(ctx, "user1", "tenant1", "users:delete")
	assert.NoError(t, err)
	assert.True(t, allowed)
}

func TestHasPermission_ResourceWildcard(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	mockRepo.EXPECT().FindPermissionsByUserAndTenant(ctx, "user1", "tenant1").Return([]string{"users:*"}, nil)

	allowed, err := svc.HasPermission(ctx, "user1", "tenant1", "users:write")
	assert.NoError(t, err)
	assert.True(t, allowed)
}

func TestHasPermission_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	mockRepo.EXPECT().FindPermissionsByUserAndTenant(ctx, "user1", "tenant1").Return(nil, errors.New("db error"))

	allowed, err := svc.HasPermission(ctx, "user1", "tenant1", "users:read")
	assert.Error(t, err)
	assert.False(t, allowed)
}

func TestGetUserPermissions_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	mockRepo.EXPECT().FindPermissionsByUserAndTenant(ctx, "user1", "tenant1").Return([]string{"users:read"}, nil)

	perms, err := svc.GetUserPermissions(ctx, "user1", "tenant1")
	assert.NoError(t, err)
	assert.Equal(t, []string{"users:read"}, perms)
}

func TestGetUserPermissions_NoRoles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	mockRepo.EXPECT().FindPermissionsByUserAndTenant(ctx, "user1", "tenant1").Return([]string{}, nil)

	perms, err := svc.GetUserPermissions(ctx, "user1", "tenant1")
	assert.NoError(t, err)
	assert.Empty(t, perms)
}

func TestGetUserRoles_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRoleRepository(ctrl)
	svc := NewDefaultPermissionService(mockRepo, nil)

	ctx := context.Background()
	expectedRoles := []model.Role{{ID: "r1", Name: "Admin"}}
	mockRepo.EXPECT().FindRolesByMembership(ctx, "m1").Return(expectedRoles, nil)

	roles, err := svc.GetUserRoles(ctx, "m1")
	assert.NoError(t, err)
	assert.Equal(t, expectedRoles, roles)
}
