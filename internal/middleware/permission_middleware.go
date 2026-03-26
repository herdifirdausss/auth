package middleware

import (
	"net/http"

	"github.com/herdifirdausss/auth/internal/service"
)

// RequirePermission checks if the authenticated user has the required permission
func RequirePermission(permService service.PermissionService, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, err := GetAuthContext(r.Context())
			if err != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			hasPerm, err := permService.HasPermission(r.Context(), authCtx.UserID, authCtx.TenantID, permission)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Internal server error")
				return
			}

			if !hasPerm {
				writeError(w, http.StatusForbidden, "Forbidden: insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
// RequireRole checks if the authenticated user has the required role
func RequireRole(permService service.PermissionService, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, err := GetAuthContext(r.Context())
			if err != nil {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}

			hasRole, err := permService.HasRole(r.Context(), authCtx.UserID, authCtx.TenantID, role)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Internal server error")
				return
			}

			if !hasRole {
				writeError(w, http.StatusForbidden, "Forbidden: insufficient role")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
