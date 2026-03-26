package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/service"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/utils"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"log/slog"
)

func TestTenantAdmin_Integration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mockPool.Close()

	auditService := mocks.NewMockAuditService(ctrl)
	
	tenantRepo := repository.NewPostgresTenantRepository(mockPool)
	membershipRepo := repository.NewPostgresTenantMembershipRepository(mockPool)
	roleRepo := repository.NewPostgresRoleRepository(mockPool)
	memRoleRepo := repository.NewPostgresMembershipRoleRepository(mockPool)

	tenantAdminService := service.NewTenantAdminService(
		mockPool,
		tenantRepo,
		membershipRepo,
		roleRepo,
		memRoleRepo,
		auditService,
	)

	h := NewTenantAdminHandler(tenantAdminService, slog.Default())

	tenantID := "tenant-123"
	userID := "user-456"
	authCtx := &middleware.AuthContext{
		TenantID: tenantID,
		UserID:   userID,
	}

	t.Run("GetSettings_Success", func(t *testing.T) {
		mockPool.ExpectQuery(`(?s).*SELECT.*FROM tenants.*WHERE id = \$1.*`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "slug", "settings", "is_active", "created_at", "updated_at"}).
				AddRow(tenantID, "Test Tenant", "test", map[string]interface{}{"key": "value"}, true, time.Now(), time.Now()))

		req := httptest.NewRequest(http.MethodGet, "/admin/tenant/settings", nil)
		req = req.WithContext(middleware.SetAuthContext(req.Context(), authCtx))
		w := httptest.NewRecorder()

		h.GetSettings(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var settings map[string]interface{}
		json.NewDecoder(w.Body).Decode(&settings)
		assert.Equal(t, "value", settings["key"])
	})

	t.Run("UpdateSettings_Success", func(t *testing.T) {
		newSettings := map[string]interface{}{"key": "new-value"}
		
		mockPool.ExpectQuery(`(?s).*SELECT.*FROM tenants.*WHERE id = \$1.*`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "name", "slug", "settings", "is_active", "created_at", "updated_at"}).
				AddRow(tenantID, "Test Tenant", "test", map[string]interface{}{"key": "old"}, true, time.Now(), time.Now()))

		mockPool.ExpectExec(`(?s).*UPDATE tenants SET settings = \$1.*WHERE id = \$2`).
			WithArgs(newSettings, tenantID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		auditService.EXPECT().Log(gomock.Any(), "tenant.settings_updated", gomock.Any(), gomock.Any(), "tenant", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		body, _ := json.Marshal(newSettings)
		req := httptest.NewRequest(http.MethodPatch, "/admin/tenant/settings", bytes.NewBuffer(body))
		req = req.WithContext(middleware.SetAuthContext(req.Context(), authCtx))
		w := httptest.NewRecorder()

		h.UpdateSettings(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("CreateRole_Success", func(t *testing.T) {
		roleReq := model.Role{
			Name:        "Editor",
			Description: utils.Ptr("Editor Role"),
			Permissions: []string{"read", "write"},
		}

		permsJSON, _ := json.Marshal(roleReq.Permissions)
		mockPool.ExpectQuery(`(?s).*INSERT INTO roles.*`).
			WithArgs(&tenantID, roleReq.Name, roleReq.Description, permsJSON, false).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).
				AddRow("role-789", time.Now(), time.Now()))

		auditService.EXPECT().Log(gomock.Any(), "role.created", gomock.Any(), gomock.Any(), "role", gomock.Any(), nil, gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		body, _ := json.Marshal(roleReq)
		req := httptest.NewRequest(http.MethodPost, "/admin/tenant/roles", bytes.NewBuffer(body))
		req = req.WithContext(middleware.SetAuthContext(req.Context(), authCtx))
		w := httptest.NewRecorder()

		h.CreateRole(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("ListMembers_Success", func(t *testing.T) {
		mockPool.ExpectQuery(`(?s).*SELECT.*FROM tenant_memberships.*WHERE tenant_id = \$1.*`).
			WithArgs(tenantID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "tenant_id", "status", "invited_by", "invited_at", "accepted_at", "created_at", "updated_at"}).
				AddRow("mem-1", "user-1", tenantID, "active", nil, time.Now(), nil, time.Now(), time.Now()))

		req := httptest.NewRequest(http.MethodGet, "/admin/tenant/members", nil)
		req = req.WithContext(middleware.SetAuthContext(req.Context(), authCtx))
		w := httptest.NewRecorder()

		h.ListMembers(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp []model.TenantMembership
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Len(t, resp, 1)
	})

	t.Run("UpdateMemberRoles_Success", func(t *testing.T) {
		membershipID := "mem-1"
		roleIDs := []string{"role-1", "role-2"}

		// 1. Find membership
		mockPool.ExpectQuery(`(?s).*SELECT.*FROM tenant_memberships.*WHERE id = \$1.*`).
			WithArgs(membershipID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "tenant_id", "status", "invited_by", "invited_at", "accepted_at", "created_at", "updated_at"}).
				AddRow(membershipID, "user-1", tenantID, "active", nil, time.Now(), nil, time.Now(), time.Now()))

		// 2. Verify roles
		for _, rid := range roleIDs {
			mockPool.ExpectQuery(`(?s).*SELECT.*FROM roles.*WHERE id = \$1.*`).
				WithArgs(rid).
				WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "name", "description", "permissions", "is_system", "created_at", "updated_at"}).
					AddRow(rid, &tenantID, "Role "+rid, nil, []byte("[]"), false, time.Now(), time.Now()))
		}

		// 3. Transaction
		mockPool.ExpectBegin()
		
		// 4. Find old roles (audit)
		mockPool.ExpectQuery(`(?s).*SELECT.*FROM roles.*JOIN membership_roles.*`).
			WithArgs(membershipID).
			WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "name", "description", "permissions", "is_system", "created_at", "updated_at"}))

		// 5. Remove all roles
		mockPool.ExpectExec(`(?s).*DELETE FROM membership_roles.*WHERE membership_id = \$1`).
			WithArgs(membershipID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		// 6. Add roles
		for _, rid := range roleIDs {
			mockPool.ExpectExec(`(?s).*INSERT INTO membership_roles.*`).
				WithArgs(membershipID, rid).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
		}

		mockPool.ExpectCommit()

		auditService.EXPECT().Log(gomock.Any(), "membership.roles_updated", gomock.Any(), gomock.Any(), "membership", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		body, _ := json.Marshal(map[string][]string{"role_ids": roleIDs})
		req := httptest.NewRequest(http.MethodPut, "/admin/tenant/members/mem-1/roles", bytes.NewBuffer(body))
		req = req.WithContext(middleware.SetAuthContext(req.Context(), authCtx))
		w := httptest.NewRecorder()

		h.UpdateMemberRoles(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
