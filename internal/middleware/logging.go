package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// responseWriter is a wrapper for http.ResponseWriter that captures the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// RequestLogger logs the start and end of an HTTP request.
// It should be placed AFTER RequestID middleware to include the request_id attribute.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap ResponseWriter to capture the status code
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:      http.StatusOK, // Default status code
		}

		// Log request start
		slog.LogAttrs(r.Context(), slog.LevelInfo, "HTTP Request started",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("proto", r.Proto),
		)

		defer func() {
			latency := time.Since(start)
			
			// Log request completion
			slog.LogAttrs(r.Context(), slog.LevelInfo, "HTTP Request completed",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", wrappedWriter.statusCode),
				slog.Duration("latency", latency),
			)
		}()

		next.ServeHTTP(wrappedWriter, r)
	})
}
