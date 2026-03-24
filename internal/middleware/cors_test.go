package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestCORS_AllowedOrigin(t *testing.T) {
	config := CORSConfig{AllowedOrigins: []string{"http://localhost:3000"}}
	mw := CORS(config)(dummyHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	config := CORSConfig{AllowedOrigins: []string{"http://localhost:3000"}}
	mw := CORS(config)(dummyHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, w.Code) // request goes through, but no cors headers
}

func TestCORS_Preflight_Success(t *testing.T) {
	config := CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         3600,
	}
	mw := CORS(config)(dummyHandler)

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "GET, POST", w.Header().Get("Access-Control-Allow-Methods"))
	assert.Equal(t, "Content-Type, Authorization", w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "3600", w.Header().Get("Access-Control-Max-Age"))
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestCORS_Preflight_Rejected(t *testing.T) {
	config := CORSConfig{AllowedOrigins: []string{"http://localhost:3000"}}
	mw := CORS(config)(dummyHandler)

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, w.Code) // Goes to dummy handler because it's rejected by CORS
}

func TestCORS_Credentials(t *testing.T) {
	config := CORSConfig{AllowedOrigins: []string{"http://localhost:3000"}, AllowCredentials: true}
	mw := CORS(config)(dummyHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORS_MaxAge(t *testing.T) {
	// Covered in TestCORS_Preflight_Success
}

func TestCORS_Methods(t *testing.T) {
	// Covered in TestCORS_Preflight_Success
}

func TestCORS_Headers(t *testing.T) {
	// Covered in TestCORS_Preflight_Success
}
