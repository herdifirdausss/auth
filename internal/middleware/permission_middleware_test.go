package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRequirePermission_Allowed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPermService := mocks.NewMockPermissionService(ctrl)
	middleware := RequirePermission(mockPermService, "users:read")

	req := httptest.NewRequest("GET", "/", nil)
	authCtx := &AuthContext{UserID: "u1", TenantID: "t1"}
	req = req.WithContext(SetAuthContext(req.Context(), authCtx))

	mockPermService.EXPECT().HasPermission(req.Context(), "u1", "t1", "users:read").Return(true, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequirePermission_Denied_403(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPermService := mocks.NewMockPermissionService(ctrl)
	middleware := RequirePermission(mockPermService, "users:write")

	req := httptest.NewRequest("GET", "/", nil)
	authCtx := &AuthContext{UserID: "u1", TenantID: "t1"}
	req = req.WithContext(SetAuthContext(req.Context(), authCtx))

	mockPermService.EXPECT().HasPermission(req.Context(), "u1", "t1", "users:write").Return(false, nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequirePermission_NoAuthContext_401(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPermService := mocks.NewMockPermissionService(ctrl)
	middleware := RequirePermission(mockPermService, "users:read")

	req := httptest.NewRequest("GET", "/", nil)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequirePermission_ServiceError_500(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPermService := mocks.NewMockPermissionService(ctrl)
	middleware := RequirePermission(mockPermService, "users:read")

	req := httptest.NewRequest("GET", "/", nil)
	authCtx := &AuthContext{UserID: "u1", TenantID: "t1"}
	req = req.WithContext(SetAuthContext(req.Context(), authCtx))

	mockPermService.EXPECT().HasPermission(req.Context(), "u1", "t1", "users:read").Return(false, errors.New("db error"))

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
