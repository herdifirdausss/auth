package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/service"
	"github.com/herdifirdausss/auth/internal/utils"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"log/slog"
	"os"
)

func TestWebAuthn_Integration(t *testing.T) {
	os.Setenv("WEBAUTHN_RP_ID", "localhost")
	os.Setenv("WEBAUTHN_RP_ORIGIN", "http://localhost:8080")

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSessionCache := mocks.NewMockSessionCache(ctrl)
	mockRateLimiter := mocks.NewMockRateLimiter(ctrl)

	userRepo := repository.NewPostgresUserRepository(mock)
	mfaRepo := repository.NewPostgresMFARepository(mock)
	sessRepo := repository.NewPostgresSessionRepository(mock)
	rfRepo := repository.NewPostgresRefreshTokenRepository(mock)
	membershipRepo := repository.NewPostgresTenantMembershipRepository(mock)

	jwtCfg := security.JWTConfig{
		SecretKey:    []byte("test-secret-at-least-32-bytes-long-123"),
		AccessExpiry: 15 * time.Minute,
	}

	webAuthnService, err := service.NewWebAuthnService(
		userRepo, mfaRepo, sessRepo, rfRepo, membershipRepo,
		jwtCfg, mockRateLimiter, mockSessionCache, utils.RealClock{}, slog.Default(),
	)
	assert.NoError(t, err)

	h := NewWebAuthnHandler(webAuthnService, slog.Default())

	userID := "user-1"
	ctx := middleware.SetAuthContext(context.Background(), &middleware.AuthContext{UserID: userID})

	t.Run("BeginRegistration_Success", func(t *testing.T) {
		mock.ExpectQuery(`(?s).*FROM users.*`).WithArgs(userID).WillReturnRows(pgxmock.NewRows([]string{"id", "email", "username"}).AddRow(userID, "test@example.com", "test"))
		mock.ExpectQuery(`(?s).*FROM mfa_methods.*`).WithArgs(userID, "webauthn").WillReturnRows(pgxmock.NewRows([]string{}))
		mockSessionCache.EXPECT().SetRaw(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/webauthn/register/begin", nil).WithContext(ctx)
		w := httptest.NewRecorder()

		h.BeginRegistration(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
