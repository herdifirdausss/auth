package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuthMiddleware_HasPermission(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	membershipRepo := repository.NewMockTenantMembershipRepository(ctrl)
	m := NewAuthMiddleware(security.JWTConfig{}, nil, nil, membershipRepo)

	t.Run("Success_ExactMatch", func(t *testing.T) {
		userID := "user-1"
		tenantID := "tenant-1"
		ctx := context.WithValue(context.Background(), authContextKey, &AuthContext{
			UserID:   userID,
			TenantID: tenantID,
		})

		membershipRepo.EXPECT().GetPermissions(gomock.Any(), userID, tenantID).Return([]string{"users:read"}, nil)

		req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
		rr := httptest.NewRecorder()

		handler := m.HasPermission("users:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Success_Wildcard", func(t *testing.T) {
		userID := "user-1"
		tenantID := "tenant-1"
		ctx := context.WithValue(context.Background(), authContextKey, &AuthContext{
			UserID:   userID,
			TenantID: tenantID,
		})

		membershipRepo.EXPECT().GetPermissions(gomock.Any(), userID, tenantID).Return([]string{"users:*"}, nil)

		req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
		rr := httptest.NewRecorder()

		handler := m.HasPermission("users:write")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Forbidden_NoPermission", func(t *testing.T) {
		userID := "user-1"
		tenantID := "tenant-1"
		ctx := context.WithValue(context.Background(), authContextKey, &AuthContext{
			UserID:   userID,
			TenantID: tenantID,
		})

		membershipRepo.EXPECT().GetPermissions(gomock.Any(), userID, tenantID).Return([]string{"profile:read"}, nil)

		req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
		rr := httptest.NewRecorder()

		handler := m.HasPermission("users:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}
