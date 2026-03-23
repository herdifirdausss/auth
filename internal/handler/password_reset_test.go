package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthHandler_ForgotPassword(t *testing.T) {
	mockService := new(mockAuthService)
	h := NewAuthHandler(mockService)

	t.Run("Success", func(t *testing.T) {
		reqBody, _ := json.Marshal(model.ForgotPasswordRequest{Email: "test@example.com"})
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()

		mockService.On("ForgotPassword", mock.Anything, "test@example.com", mock.Anything, mock.Anything).Return(nil)

		h.ForgotPassword(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Equal(t, "success", resp["status"])
	})
}

func TestAuthHandler_ResetPassword(t *testing.T) {
	mockService := new(mockAuthService)
	h := NewAuthHandler(mockService)

	t.Run("Success", func(t *testing.T) {
		reqBody, _ := json.Marshal(model.ResetPasswordRequest{
			Token:       "valid-token",
			NewPassword: "NewSecurePassword123!",
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewBuffer(reqBody))
		w := httptest.NewRecorder()

		mockService.On("ResetPassword", mock.Anything, "valid-token", "NewSecurePassword123!", mock.Anything, mock.Anything).Return(nil)

		h.ResetPassword(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Equal(t, "success", resp["status"])
	})
}
