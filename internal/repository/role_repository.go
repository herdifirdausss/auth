package repository

import (
	"context"

	"github.com/herdifirdausss/auth/internal/model"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type RoleRepository interface {
	FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error)
	FindRolesByMembership(ctx context.Context, membershipID string) ([]model.Role, error)
}
