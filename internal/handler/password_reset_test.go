package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuthHandler_ForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	t.Run("Success", func(t *testing.T) {
		reqBody, _ := json.Marshal(model.ForgotPasswordRequest{Email: "test@example.com"})
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()

		mockService.EXPECT().ForgotPassword(gomock.Any(), "test@example.com", gomock.Any(), gomock.Any()).Return(nil)

		h.ForgotPassword(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Equal(t, "success", resp["status"])
	})
	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader("invalid-json"))
		w := httptest.NewRecorder()
		h.ForgotPassword(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("MethodNotAllowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/forgot-password", nil)
		w := httptest.NewRecorder()
		h.ForgotPassword(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestAuthHandler_ResetPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockService := mocks.NewMockAuthService(ctrl)
	h := NewAuthHandler(mockService)

	t.Run("Success", func(t *testing.T) {
		reqBody, _ := json.Marshal(model.ResetPasswordRequest{
			Token:       "valid-token",
			NewPassword: "NewSecurePassword123!",
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()

		mockService.EXPECT().ResetPassword(gomock.Any(), "valid-token", "NewSecurePassword123!", gomock.Any(), gomock.Any()).Return(nil)

		h.ResetPassword(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Equal(t, "success", resp["status"])
	})
	t.Run("WeakPassword", func(t *testing.T) {
		reqBody, _ := json.Marshal(model.ResetPasswordRequest{
			Token:       "valid-token",
			NewPassword: "weak",
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()

		mockService.EXPECT().ResetPassword(gomock.Any(), "valid-token", "weak", gomock.Any(), gomock.Any()).
			Return(fmt.Errorf("weak password: must be at least 8 characters"))

		h.ResetPassword(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
