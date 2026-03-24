package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestAuthMiddleware_HasPermission(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	membershipRepo := mocks.NewMockTenantMembershipRepository(ctrl)
	m := NewAuthMiddleware(security.JWTConfig{}, nil, nil, membershipRepo)

	t.Run("Success_ExactMatch", func(t *testing.T) {
		userID := "user-1"
		tenantID := "tenant-1"
		ctx := context.WithValue(context.Background(), authContextKey, &AuthContext{
			UserID:   userID,
			TenantID: tenantID,
		})

		membershipRepo.EXPECT().FindPermissionsByUserAndTenant(gomock.Any(), userID, tenantID).Return([]string{"users:read"}, nil)

		req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
		rr := httptest.NewRecorder()

		handler := m.HasPermission("users:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Success_Wildcard", func(t *testing.T) {
		userID := "user-1"
		tenantID := "tenant-1"
		ctx := context.WithValue(context.Background(), authContextKey, &AuthContext{
			UserID:   userID,
			TenantID: tenantID,
		})

		membershipRepo.EXPECT().FindPermissionsByUserAndTenant(gomock.Any(), userID, tenantID).Return([]string{"users:*"}, nil)

		req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
		rr := httptest.NewRecorder()

		handler := m.HasPermission("users:write")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Forbidden_NoPermission", func(t *testing.T) {
		userID := "user-1"
		tenantID := "tenant-1"
		ctx := context.WithValue(context.Background(), authContextKey, &AuthContext{
			UserID:   userID,
			TenantID: tenantID,
		})

		membershipRepo.EXPECT().FindPermissionsByUserAndTenant(gomock.Any(), userID, tenantID).Return([]string{"profile:read"}, nil)

		req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
		rr := httptest.NewRecorder()

		handler := m.HasPermission("users:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestAuthMiddleware_Authenticate(t *testing.T) {
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

	m := NewAuthMiddleware(jwtCfg, sessionRepo, sessionCache, membershipRepo)

	t.Run("Success_CacheHit", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
			Tid: "tenant-1",
		}
		token, _ := security.GenerateAccessToken(jwtCfg, claims)

		cachedSession := &redis.CachedSession{
			SessionID:     "session-1",
			UserID:        "user-1",
			TenantID:      "tenant-1",
			MFAVerified:   true,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			IdleTimeoutAt: time.Now().Add(30 * time.Minute),
		}

		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(cachedSession, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, err := GetAuthContext(r.Context())
			assert.NoError(t, err)
			assert.Equal(t, "user-1", authCtx.UserID)
			assert.Equal(t, "session-1", authCtx.SessionID)
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Success_CacheMiss_DBHit", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		}
		token, _ := security.GenerateAccessToken(jwtCfg, claims)

		dbSession := &model.Session{
			ID:            "session-1",
			UserID:        "user-1",
			MFAVerified:   true,
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			IdleTimeoutAt: time.Now().Add(30 * time.Minute),
		}

		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(nil, nil)
		sessionRepo.EXPECT().FindByID(gomock.Any(), "session-1").Return(dbSession, nil)
		sessionCache.EXPECT().Set(gomock.Any(), "session-1", gomock.Any()).Return(nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Unauthorized_MissingToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized_InvalidToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized_ExpiredSession", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		}
		token, _ := security.GenerateAccessToken(jwtCfg, claims)

		cachedSession := &redis.CachedSession{
			SessionID:     "session-1",
			UserID:        "user-1",
			ExpiresAt:     time.Now().Add(-1 * time.Hour),
			IdleTimeoutAt: time.Now().Add(30 * time.Minute),
		}

		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(cachedSession, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized_IdleTimeout", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		}
		token, _ := security.GenerateAccessToken(jwtCfg, claims)

		cachedSession := &redis.CachedSession{
			SessionID:     "session-1",
			UserID:        "user-1",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			IdleTimeoutAt: time.Now().Add(-1 * time.Minute),
		}

		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(cachedSession, nil)
		sessionRepo.EXPECT().RevokeByID(gomock.Any(), "session-1", "idle_timeout", "system").Return(nil)
		sessionCache.EXPECT().Delete(gomock.Any(), "user-1", "session-1").Return(nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized_SIDMismatch", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-wrong",
		}
		token, _ := security.GenerateAccessToken(jwtCfg, claims)

		cachedSession := &redis.CachedSession{
			SessionID:     "session-1",
			UserID:        "user-1",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			IdleTimeoutAt: time.Now().Add(30 * time.Minute),
		}

		sessionCache.EXPECT().Get(gomock.Any(), "session-wrong").Return(cachedSession, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, rr.Body.String(), "Invalid session token")
	})

	t.Run("Success_DebouncedActivityUpdate", func(t *testing.T) {
		claims := security.JWTClaims{
			Sub: "user-1",
			Sid: "session-1",
		}
		token, _ := security.GenerateAccessToken(jwtCfg, claims)

		// Set IdleTimeout to more than 30 mins ago to trigger shouldUpdateActivity
		// shouldUpdateActivity checks if lastActivity (IdleTimeout - 30min) is more than 1 min ago.
		// Wait, look at helpers.go:
		// func shouldUpdateActivity(lastActivity time.Time) bool {
		// 	return time.Since(lastActivity) > 1*time.Minute
		// }
		// So if IdleTimeoutAt is Now + 10min, lastActivity is Now - 20min. 20min > 1min -> true.

		cachedSession := &redis.CachedSession{
			SessionID:     "session-1",
			UserID:        "user-1",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
			IdleTimeoutAt: time.Now().Add(10 * time.Minute),
		}

		sessionCache.EXPECT().Get(gomock.Any(), "session-1").Return(cachedSession, nil)
		sessionRepo.EXPECT().UpdateActivity(gomock.Any(), "session-1").Return(nil)
		sessionCache.EXPECT().Set(gomock.Any(), "session-1", gomock.Any()).Return(nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
