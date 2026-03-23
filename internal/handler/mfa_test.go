package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/herdifirdausss/auth/internal/service"
	"go.uber.org/mock/gomock"
)

func TestMFAHandler_Setup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mfaSvc := service.NewMockMFAService(ctrl)
	h := NewMFAHandler(mfaSvc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/mfa/setup", nil)
	
	ctx := middleware.SetAuthContext(r.Context(), &middleware.AuthContext{UserID: "user-1", Email: "user@example.com"})
	r = r.WithContext(ctx)

	mfaSvc.EXPECT().SetupTOTP(gomock.Any(), "user-1", "user@example.com").Return(&model.SetupResponse{Secret: "ABC"}, nil)

	h.Setup(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMFAHandler_VerifySetup(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mfaSvc := service.NewMockMFAService(ctrl)
	h := NewMFAHandler(mfaSvc)

	reqBody, _ := json.Marshal(model.VerifySetupRequest{OTPCode: "123456"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/mfa/verify-setup", bytes.NewBuffer(reqBody))
	
	ctx := middleware.SetAuthContext(r.Context(), &middleware.AuthContext{UserID: "user-1", Email: "user@example.com"})
	r = r.WithContext(ctx)

	mfaSvc.EXPECT().VerifySetup(gomock.Any(), "user-1", "123456").Return(&model.VerifySetupResponse{BackupCodes: []string{"C1"}}, nil)

	h.VerifySetup(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMFAHandler_Challenge(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mfaSvc := service.NewMockMFAService(ctrl)
	h := NewMFAHandler(mfaSvc)

	reqBody, _ := json.Marshal(model.ChallengeRequest{MFAToken: "mfa-token", OTPCode: "123456"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/mfa/challenge", bytes.NewBuffer(reqBody))

	mfaSvc.EXPECT().Challenge(gomock.Any(), "mfa-token", "123456", gomock.Any(), gomock.Any(), "").Return(&model.LoginResponse{AccessToken: "access", RefreshToken: "refresh"}, nil)

	h.Challenge(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
}
