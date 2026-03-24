package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestLogoutHandler_Logout_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	authCtx := &middleware.AuthContext{
		SessionID: "sess-1",
		UserID:    "user-1",
		TokenHash: "hash-1",
	}

	mockService.EXPECT().Logout(gomock.Any(), "sess-1", "user-1", "hash-1").Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req = req.WithContext(middleware.SetAuthContext(req.Context(), authCtx))
	
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	// Check cookie cleared
	cookies := w.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "refresh_token" {
			refreshCookie = c
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, "", refreshCookie.Value)
}

func TestLogoutHandler_LogoutAll_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	authCtx := &middleware.AuthContext{
		UserID: "user-1",
	}

	mockService.EXPECT().LogoutAll(gomock.Any(), "user-1").Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout-all", nil)
	req = req.WithContext(middleware.SetAuthContext(req.Context(), authCtx))
	
	w := httptest.NewRecorder()

	h.LogoutAll(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogoutHandler_Unauthorized(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	// No context
	
	w := httptest.NewRecorder()

	h.Logout(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
