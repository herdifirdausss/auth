package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockMFAService struct {
	mock.Mock
}

func (m *mockMFAService) SetupTOTP(ctx context.Context, userID, email string) (*model.SetupResponse, error) {
	args := m.Called(ctx, userID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SetupResponse), args.Error(1)
}

func (m *mockMFAService) VerifySetup(ctx context.Context, userID, otpCode string) (*model.VerifySetupResponse, error) {
	args := m.Called(ctx, userID, otpCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.VerifySetupResponse), args.Error(1)
}

func (m *mockMFAService) Challenge(ctx context.Context, mfaToken, otpCode string, ip, ua, fingerprint string) (*model.LoginResponse, error) {
	args := m.Called(ctx, mfaToken, otpCode, ip, ua, fingerprint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.LoginResponse), args.Error(1)
}

func TestMFAHandler_Setup(t *testing.T) {
	mfaSvc := new(mockMFAService)
	h := NewMFAHandler(mfaSvc)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/mfa/setup", nil)
	
	ctx := middleware.SetAuthContext(r.Context(), &middleware.AuthContext{UserID: "user-1", Email: "user@example.com"})
	r = r.WithContext(ctx)

	mfaSvc.On("SetupTOTP", mock.Anything, "user-1", "user@example.com").Return(&model.SetupResponse{Secret: "ABC"}, nil)

	h.Setup(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	mfaSvc.AssertExpectations(t)
}

func TestMFAHandler_VerifySetup(t *testing.T) {
	mfaSvc := new(mockMFAService)
	h := NewMFAHandler(mfaSvc)

	reqBody, _ := json.Marshal(model.VerifySetupRequest{OTPCode: "123456"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/mfa/verify-setup", bytes.NewBuffer(reqBody))
	
	ctx := middleware.SetAuthContext(r.Context(), &middleware.AuthContext{UserID: "user-1", Email: "user@example.com"})
	r = r.WithContext(ctx)

	mfaSvc.On("VerifySetup", mock.Anything, "user-1", "123456").Return(&model.VerifySetupResponse{BackupCodes: []string{"C1"}}, nil)

	h.VerifySetup(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	mfaSvc.AssertExpectations(t)
}

func TestMFAHandler_Challenge(t *testing.T) {
	mfaSvc := new(mockMFAService)
	h := NewMFAHandler(mfaSvc)

	reqBody, _ := json.Marshal(model.ChallengeRequest{MFAToken: "mfa-token", OTPCode: "123456"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/mfa/challenge", bytes.NewBuffer(reqBody))

	mfaSvc.On("Challenge", mock.Anything, "mfa-token", "123456", mock.Anything, mock.Anything, "").Return(&model.LoginResponse{AccessToken: "access", RefreshToken: "refresh"}, nil)

	h.Challenge(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
	mfaSvc.AssertExpectations(t)
}
