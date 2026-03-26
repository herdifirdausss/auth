package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/stretchr/testify/assert"
)

func TestUserHandler_Me(t *testing.T) {
	h := NewUserHandler()

	t.Run("Success", func(t *testing.T) {
		authCtx := &middleware.AuthContext{
			UserID:      "user-123",
			Email:       "test@example.com",
			TenantID:    "tenant-456",
			SessionID:   "session-789",
			MFAVerified: true,
		}

		ctx := middleware.SetAuthContext(context.Background(), authCtx)
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil).WithContext(ctx)
		w := httptest.NewRecorder()

		h.Me(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(t, err)
		assert.Equal(t, "success", resp["status"])

		data := resp["data"].(map[string]interface{})
		assert.Equal(t, "user-123", data["user_id"])
		assert.Equal(t, "tenant-456", data["tenant_id"])
		assert.Equal(t, true, data["mfa_verified"])
	})

	t.Run("Unauthorized_MissingContext", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		w := httptest.NewRecorder()

		h.Me(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Unauthorized")
	})
}
