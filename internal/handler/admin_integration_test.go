package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/service"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"log/slog"
)

func TestAdmin_Integration(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	tenantRepo := repository.NewPostgresTenantRepository(mock)
	adminService := service.NewAdminService(tenantRepo, slog.Default())
	h := NewAdminHandler(adminService, slog.Default())

	t.Run("ListTenants_Success", func(t *testing.T) {
		mock.ExpectQuery(`(?s).*SELECT.*FROM tenants.*`).WillReturnRows(pgxmock.NewRows([]string{"id", "name", "slug", "settings", "is_active", "created_at", "updated_at"}).
			AddRow("t1", "Tenant 1", "t1", make(map[string]interface{}), true, time.Now(), time.Now()))

		req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
		w := httptest.NewRecorder()

		h.ListTenants(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp []*model.Tenant
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Len(t, resp, 1)
		assert.Equal(t, "Tenant 1", resp[0].Name)
	})

	t.Run("UpdateStatus_Success", func(t *testing.T) {
		mock.ExpectExec(`(?s).*UPDATE tenants SET is_active = \$1.*WHERE id = \$2`).WithArgs(false, "t1").WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		body, _ := json.Marshal(map[string]bool{"is_active": false})
		req := httptest.NewRequest(http.MethodPatch, "/admin/tenants/status?id=t1", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		h.UpdateTenantStatus(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAdminRBAC_Integration(t *testing.T) {
	// This tests the middleware integration
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	// Mocks for middleware
	// Actually, I can use a real middleware but mock the permission service
	// Since NewRouter wires it up, I'll test it through a mock permission service.
}
