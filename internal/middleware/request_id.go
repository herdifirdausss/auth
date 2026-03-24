package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type reqKey string

const requestIDKey reqKey = "request_id"

// RequestID adds a unique X-Request-ID header to the response and context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		
		w.Header().Set("X-Request-ID", id)

		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID gets the request ID from context.
func GetRequestID(ctx context.Context) string {
	if val, ok := ctx.Value(requestIDKey).(string); ok {
		return val
	}
	return ""
}
