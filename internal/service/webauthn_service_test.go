package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/utils"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func setupWebAuthnTest(t *testing.T) (*WebAuthnServiceImpl, *mocks.MockUserRepository, *mocks.MockMFARepository, *mocks.MockSessionRepository, *mocks.MockRefreshTokenRepository, *mocks.MockTenantMembershipRepository, *mocks.MockSessionCache, *gomock.Controller) {
	os.Setenv("WEBAUTHN_RP_ID", "localhost")
	os.Setenv("WEBAUTHN_RP_ORIGIN", "http://localhost:8080")

	ctrl := gomock.NewController(t)

	userRepo := mocks.NewMockUserRepository(ctrl)
	mfaRepo := mocks.NewMockMFARepository(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)
	sessionCache := mocks.NewMockSessionCache(ctrl)
	rateLimiter := mocks.NewMockRateLimiter(ctrl)

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("test-secret-at-least-32-bytes-long-123"),
		AccessExpiry: 15 * time.Minute,
	}

	s, _ := NewWebAuthnService(
		userRepo,
		mfaRepo,
		sessRepo,
		rfRepo,
		membershipRepo,
		jwtConfig,
		rateLimiter,
		sessionCache,
		utils.RealClock{},
		slog.Default(),
	)

	return s, userRepo, mfaRepo, sessRepo, rfRepo, membershipRepo, sessionCache, ctrl
}

func TestWebAuthnService_BeginRegistration(t *testing.T) {
	s, userRepo, mfaRepo, _, _, _, sessionCache, ctrl := setupWebAuthnTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	userID := "user-1"
	user := &model.User{ID: userID, Email: "test@example.com", Username: "test"}

	userRepo.EXPECT().FindByID(ctx, userID).Return(user, nil)
	mfaRepo.EXPECT().FindAllByUserIDAndType(ctx, userID, "webauthn").Return(nil, nil)
	sessionCache.EXPECT().SetRaw(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	options, err := s.BeginRegistration(ctx, userID)
	assert.NoError(t, err)
	assert.NotNil(t, options)
}

func TestWebAuthnService_BeginLogin(t *testing.T) {
	s, userRepo, mfaRepo, _, _, _, sessionCache, ctrl := setupWebAuthnTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	email := "test@example.com"
	user := &model.User{ID: "user-1", Email: email, Username: "test"}

	userRepo.EXPECT().FindByEmail(ctx, email).Return(user, nil)
	userRepo.EXPECT().FindByID(ctx, user.ID).Return(user, nil)

	credBytes, _ := json.Marshal(webauthn.Credential{ID: []byte("cred-1")})
	mfaMethod := &model.MFAMethod{
		ID:              "mfa-1",
		UserID:          user.ID,
		MethodType:      "webauthn",
		SecretEncrypted: string(credBytes),
		IsActive:        true,
	}
	mfaRepo.EXPECT().FindAllByUserIDAndType(ctx, user.ID, "webauthn").Return([]*model.MFAMethod{mfaMethod}, nil)
	sessionCache.EXPECT().SetRaw(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	options, err := s.BeginLogin(ctx, email)
	assert.NoError(t, err)
	assert.NotNil(t, options)
}

func TestWebAuthnService_FinishLogin_Failure_NoSession(t *testing.T) {
	s, _, _, _, _, _, sessionCache, ctrl := setupWebAuthnTest(t)
	defer ctrl.Finish()

	ctx := context.Background()
	sessionID := "invalid"

	sessionCache.EXPECT().GetRaw(ctx, "webauthn_login:"+sessionID).Return("", fmt.Errorf("not found"))

	res, err := s.FinishLogin(ctx, sessionID, []byte("{}"))
	assert.Error(t, err)
	assert.Nil(t, res)
}
