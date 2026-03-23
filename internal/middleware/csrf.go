package middleware

import (
	"net/http"

	myredis "github.com/herdifirdausss/auth/internal/infrastructure/redis"
)

// CSRFProtection is a middleware that validates CSRF tokens.
func CSRFProtection(csrfManager *myredis.CSRFManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				http.Error(w, "missing CSRF token", http.StatusForbidden)
				return
			}

			authCtx, err := GetAuthContext(r.Context())
			if err != nil || authCtx.SessionID == "" {
				http.Error(w, "unauthorized or missing session", http.StatusUnauthorized)
				return
			}

			valid, err := csrfManager.Validate(r.Context(), authCtx.SessionID, token)
			if err != nil {
				http.Error(w, "error validating CSRF token", http.StatusInternalServerError)
				return
			}

			if !valid {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
