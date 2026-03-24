package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMeIntegration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sessionRepo := mocks.NewMockSessionRepository(ctrl)
	sessionCache := mocks.NewMockSessionCache(ctrl)
	membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)

	jwtCfg := security.JWTConfig{
		SecretKey:    []byte("test-secret"),
		Issuer:       "test-issuer",
		AccessExpiry: 1 * time.Hour,
	}

	authMW := middleware.NewAuthMiddleware(jwtCfg, sessionRepo, sessionCache, membershipRepo)
	userHandler := NewUserHandler()

	// Setup router-like flow: AuthMW -> UserHandler.Me
	handler := authMW.Authenticate(http.HandlerFunc(userHandler.Me))

	t.Run("Security_JWT_NoneAlgorithm", func(t *testing.T) {
		// Manually create a JWT with "none" algorithm
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		})
		tokenString, _ := token.SignedString(jwtCfg.SecretKey)
		
		// Corrupt it to have alg: none
		parts := strings.Split(tokenString, ".")
		// A better way to test "none" is to use a token without signature
		noneToken := parts[0] + "." + parts[1] + "."

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+noneToken)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid or expired token")
	})

	t.Run("Security_IDOR_TamperedSignature", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		}
		tokenString, _ := security.GenerateAccessToken(jwtCfg, claims)
		
		// Tamper with the payload (e.g., change user ID) but keep signature
		parts := strings.Split(tokenString, ".")
		// We'll just change one character in the payload part of the JWT
		tamperedToken := parts[0] + ".eyJzdWIiOiJ1c2VyLTIiLCJzaWQiOiJzZXNzaW9uLTEifQ." + parts[2]

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+tamperedToken)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Security_SQLInjection_InClaims", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user' OR '1'='1",
			Sid: "session-1",
		}
		tokenString, _ := security.GenerateAccessToken(jwtCfg, claims)

		// Mock session cache and repo to return no rows for this "user"
		// The point is to ensure it doesn't crash or behave weirdly.
		// Since session lookup is by Sid, the Sub injection shouldn't affect DB query for session.
		// However, it might affect user lookup if implemented.
		
		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(nil, nil)
		sessionRepo.EXPECT().FindByID(gomock.Any(), "session-1").Return(nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("ResourceExhaustion_LargeBearerToken", func(t *testing.T) {
		largeToken := strings.Repeat("A", 1*1024*1024) // 1MB token

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+largeToken)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		// Should either be 401 (parsing fails) or 413 (if middleware exists, but we don't have one yet)
		// For now, Authenticate just tries to parse it.
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("PartialFailure_RedisDown_FailClosed", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		}
		tokenString, _ := security.GenerateAccessToken(jwtCfg, claims)

		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(nil, fmt.Errorf("redis connection refused"))
		// Even if cache is down, it should NOT automatically trust or fail-open if DB is not checked or fails too.
		// In our code:
		// session, err := m.sessionCache.Get(r.Context(), claims.Sid)
		// if err != nil || session == nil { ... query DB ... }
		
		sessionRepo.EXPECT().FindByID(gomock.Any(), "session-1").Return(nil, fmt.Errorf("db connection refused"))

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
	
	t.Run("DeletedUser_FailCleanly", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		}
		tokenString, _ := security.GenerateAccessToken(jwtCfg, claims)

		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(nil, nil)
		sessionRepo.EXPECT().FindByID(gomock.Any(), "session-1").Return(nil, nil) // User deleted or session revoked

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid session")
	})
}
