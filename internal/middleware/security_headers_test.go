package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders_AllPresent(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, "max-age=31536000; includeSubDomains; preload", w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "0", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "default-src 'self'; script-src 'self'; style-src 'self'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "camera=(), microphone=(), geolocation=()", w.Header().Get("Permissions-Policy"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestSecurityHeaders_HSTSValue(t *testing.T) {
	// Covered in TestSecurityHeaders_AllPresent
}

func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	// Covered in TestSecurityHeaders_AllPresent
}

func TestSecurityHeaders_ContentTypeOptions(t *testing.T) {
	// Covered in TestSecurityHeaders_AllPresent
}

func TestSecurityHeaders_CSP(t *testing.T) {
	// Covered in TestSecurityHeaders_AllPresent
}

func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	// Covered in TestSecurityHeaders_AllPresent
}

func TestSecurityHeaders_CacheControl(t *testing.T) {
	// Covered in TestSecurityHeaders_AllPresent
}
