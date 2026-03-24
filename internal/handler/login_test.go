package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestLoginHandler_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	reqBody := model.LoginRequest{
		Email:    "test@example.com",
		Password: "Password123!",
	}
	body, _ := json.Marshal(reqBody)

	res := &model.LoginResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	mockService.EXPECT().Login(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(res, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "success", resp["status"])
	
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, "access-token", data["access_token"])
	
	// Check cookie
	cookies := w.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "refresh_token" {
			refreshCookie = c
		}
	}
	assert.NotNil(t, refreshCookie)
	assert.Equal(t, "refresh-token", refreshCookie.Value)
	assert.True(t, refreshCookie.HttpOnly)
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	reqBody := model.LoginRequest{
		Email:    "wrong@example.com",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(reqBody)

	mockService.EXPECT().Login(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, fmt.Errorf("invalid email or password"))

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "error", resp["status"])
	assert.Equal(t, "invalid email or password", resp["message"])
}

func TestLoginHandler_TooManyAttempts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	reqBody := model.LoginRequest{
		Email:    "attacker@example.com",
		Password: "any",
	}
	body, _ := json.Marshal(reqBody)

	mockService.EXPECT().Login(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, fmt.Errorf("too many login attempts"))

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	h.Login(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
