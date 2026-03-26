package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAdminHandler_ListTenants(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockAdminService(ctrl)
	h := NewAdminHandler(mockService, slog.Default())

	t.Run("Success", func(t *testing.T) {
		tenants := []*model.Tenant{{ID: "1", Name: "T1"}}
		mockService.EXPECT().ListTenants(gomock.Any()).Return(tenants, nil)

		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		w := httptest.NewRecorder()

		h.ListTenants(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp []*model.Tenant
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Len(t, resp, 1)
		assert.Equal(t, "T1", resp[0].Name)
	})

	t.Run("Error", func(t *testing.T) {
		mockService.EXPECT().ListTenants(gomock.Any()).Return(nil, fmt.Errorf("error"))

		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		w := httptest.NewRecorder()

		h.ListTenants(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestAdminHandler_UpdateTenantStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockAdminService(ctrl)
	h := NewAdminHandler(mockService, slog.Default())

	t.Run("Success", func(t *testing.T) {
		mockService.EXPECT().UpdateTenantStatus(gomock.Any(), "1", true).Return(nil)

		body, _ := json.Marshal(map[string]bool{"is_active": true})
		req := httptest.NewRequest(http.MethodPatch, "/admin/tenants/status?id=1", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		h.UpdateTenantStatus(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("MissingID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/admin/tenants/status", nil)
		w := httptest.NewRecorder()

		h.UpdateTenantStatus(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
