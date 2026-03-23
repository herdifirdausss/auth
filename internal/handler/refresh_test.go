package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"github.com/herdifirdausss/auth/internal/service"
)

func TestRefreshHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := service.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	res := &model.LoginResponse{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}

	mockService.EXPECT().RefreshToken(gomock.Any(), "old-refresh", gomock.Any(), gomock.Any()).Return(res, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "old-refresh"})
	w := httptest.NewRecorder()

	h.RefreshToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "success", resp["status"])
	
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, "new-access", data["access_token"])
	
	// Check cookie
	cookies := w.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "refresh_token" {
			refreshCookie = c
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, "new-refresh", refreshCookie.Value)
}

func TestRefreshHandler_NoCookie(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := service.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", nil)
	w := httptest.NewRecorder()

	h.RefreshToken(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefreshHandler_ReuseDetected(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := service.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	mockService.EXPECT().RefreshToken(gomock.Any(), "reused-token", gomock.Any(), gomock.Any()).
		Return(nil, fmt.Errorf("suspicious activity detected"))

	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "reused-token"})
	w := httptest.NewRecorder()

	h.RefreshToken(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
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
	assert.True(t, refreshCookie.Expires.Before(time.Now()))
}
