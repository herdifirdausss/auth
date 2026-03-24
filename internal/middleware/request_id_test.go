package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestID_Generated(t *testing.T) {
	handler := RequestID(dummyHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	id := w.Header().Get("X-Request-ID")
	assert.NotEmpty(t, id)
}

func TestRequestID_Unique(t *testing.T) {
	handler := RequestID(dummyHandler)

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	assert.NotEqual(t, w1.Header().Get("X-Request-ID"), w2.Header().Get("X-Request-ID"))
}

func TestRequestID_InHeader(t *testing.T) {
	// Covered in TestRequestID_Generated
}

func TestRequestID_InContext(t *testing.T) {
	var ctxID string
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = GetRequestID(r.Context())
	})

	handler := RequestID(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	headerID := w.Header().Get("X-Request-ID")
	assert.NotEmpty(t, ctxID)
	assert.Equal(t, headerID, ctxID)
}

func TestRequestID_NotInContext(t *testing.T) {
	id := GetRequestID(context.Background())
	assert.Empty(t, id)
}
