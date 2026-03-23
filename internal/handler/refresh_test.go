package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockAuthService struct{ mock.Mock }

func (m *mockAuthService) Logout(ctx context.Context, sessionID, userID, tokenHash string) error {
	args := m.Called(ctx, sessionID, userID, tokenHash)
	return args.Error(0)
}

func (m *mockAuthService) LogoutAll(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockAuthService) Register(ctx context.Context, req *model.RegisterRequest, ip string, ua string) (*model.RegisterResponse, error) {
	args := m.Called(ctx, req, ip, ua)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RegisterResponse), args.Error(1)
}

func (m *mockAuthService) VerifyEmail(ctx context.Context, token string, ip string, ua string) error {
	return m.Called(ctx, token, ip, ua).Error(0)
}

func (m *mockAuthService) Login(ctx context.Context, req *model.LoginRequest, ip string, ua string) (*model.LoginResponse, error) {
	args := m.Called(ctx, req, ip, ua)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.LoginResponse), args.Error(1)
}

func (m *mockAuthService) RefreshToken(ctx context.Context, token string, ip string, ua string) (*model.LoginResponse, error) {
	args := m.Called(ctx, token, ip, ua)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.LoginResponse), args.Error(1)
}

func (m *mockAuthService) ForgotPassword(ctx context.Context, email, ip, ua string) error {
	return m.Called(ctx, email, ip, ua).Error(0)
}

func (m *mockAuthService) ResetPassword(ctx context.Context, token, newPassword, ip, ua string) error {
	return m.Called(ctx, token, newPassword, ip, ua).Error(0)
}

func TestRefreshHandler_Success(t *testing.T) {
	mockService := new(mockAuthService)
	h := NewAuthHandler(mockService)

	res := &model.LoginResponse{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}

	mockService.On("RefreshToken", mock.Anything, "old-refresh", mock.Anything, mock.Anything).Return(res, nil)

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
	mockService := new(mockAuthService)
	h := NewAuthHandler(mockService)

	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", nil)
	w := httptest.NewRecorder()

	h.RefreshToken(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefreshHandler_ReuseDetected(t *testing.T) {
	mockService := new(mockAuthService)
	h := NewAuthHandler(mockService)

	mockService.On("RefreshToken", mock.Anything, "reused-token", mock.Anything, mock.Anything).
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
