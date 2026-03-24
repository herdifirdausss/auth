package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	myredis "github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func setupTestRedis() (*miniredis.Miniredis, *myredis.CSRFManager) {
	mr, _ := miniredis.Run()
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	manager := myredis.NewCSRFManager(client, time.Hour)
	return mr, manager
}

func TestCSRF_ValidToken(t *testing.T) {
	mr, manager := setupTestRedis()
	defer mr.Close()

	ctx := context.Background()
	token, _ := manager.Generate(ctx, "session123")

	handler := CSRFProtection(manager)(dummyHandler)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", token)
	authCtx := SetAuthContext(req.Context(), &AuthContext{SessionID: "session123"})
	req = req.WithContext(authCtx)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_InvalidToken_403(t *testing.T) {
	mr, manager := setupTestRedis()
	defer mr.Close()

	ctx := context.Background()
	manager.Generate(ctx, "session123")

	handler := CSRFProtection(manager)(dummyHandler)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "invalid-token")
	authCtx := SetAuthContext(req.Context(), &AuthContext{SessionID: "session123"})
	req = req.WithContext(authCtx)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_MissingToken_403(t *testing.T) {
	mr, manager := setupTestRedis()
	defer mr.Close()

	handler := CSRFProtection(manager)(dummyHandler)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// no token
	authCtx := SetAuthContext(req.Context(), &AuthContext{SessionID: "session123"})
	req = req.WithContext(authCtx)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRF_SkipGET(t *testing.T) {
	mr, manager := setupTestRedis()
	defer mr.Close()

	handler := CSRFProtection(manager)(dummyHandler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_SkipHEAD(t *testing.T) {
	mr, manager := setupTestRedis()
	defer mr.Close()

	handler := CSRFProtection(manager)(dummyHandler)
	req := httptest.NewRequest(http.MethodHead, "/", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_SkipOPTIONS(t *testing.T) {
	mr, manager := setupTestRedis()
	defer mr.Close()

	handler := CSRFProtection(manager)(dummyHandler)
	req := httptest.NewRequest(http.MethodOptions, "/", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRF_RedisError(t *testing.T) {
	mr, manager := setupTestRedis()
	mr.Close() // Close immediately to simulate error

	handler := CSRFProtection(manager)(dummyHandler)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	authCtx := SetAuthContext(req.Context(), &AuthContext{SessionID: "session123"})
	req = req.WithContext(authCtx)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
