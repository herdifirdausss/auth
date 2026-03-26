package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestWebAuthnHandler_BeginRegistration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockWebAuthnService(ctrl)
	h := NewWebAuthnHandler(mockService, slog.Default())

	userID := "user-1"
	ctx := middleware.SetAuthContext(context.Background(), &middleware.AuthContext{UserID: userID})

	t.Run("Success", func(t *testing.T) {
		options := &protocol.CredentialCreation{}
		mockService.EXPECT().BeginRegistration(gomock.Any(), userID).Return(options, nil)

		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/webauthn/register/begin", nil).WithContext(ctx)
		w := httptest.NewRecorder()

		h.BeginRegistration(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/webauthn/register/begin", nil)
		w := httptest.NewRecorder()

		h.BeginRegistration(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestWebAuthnHandler_BeginLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockWebAuthnService(ctrl)
	h := NewWebAuthnHandler(mockService, slog.Default())

	t.Run("Success", func(t *testing.T) {
		email := "test@example.com"
		options := &protocol.CredentialAssertion{}
		mockService.EXPECT().BeginLogin(gomock.Any(), email).Return(options, nil)

		body, _ := json.Marshal(map[string]string{"email": email})
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/webauthn/login/begin", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		h.BeginLogin(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Error", func(t *testing.T) {
		mockService.EXPECT().BeginLogin(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("error"))

		body, _ := json.Marshal(map[string]string{"email": "fail@example.com"})
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/webauthn/login/begin", bytes.NewBuffer(body))
		w := httptest.NewRecorder()

		h.BeginLogin(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
