package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
)

type AuthMiddleware struct {
	jwtConfig    security.JWTConfig
	sessionRepo  repository.SessionRepository
	sessionCache redis.SessionCache
	membershipRepo repository.TenantMembershipRepository
}

func NewAuthMiddleware(cfg security.JWTConfig, repo repository.SessionRepository, cache redis.SessionCache, membershipRepo repository.TenantMembershipRepository) *AuthMiddleware {
	return &AuthMiddleware{
		jwtConfig:    cfg,
		sessionRepo:  repo,
		sessionCache: cache,
		membershipRepo: membershipRepo,
	}
}

func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract Token
		token, err := extractBearerToken(r)
		if err != nil {
			writeUnauthorized(w, "Authentication required")
			return
		}

		// 2. Validate JWT
		claims, err := security.ValidateAccessToken(m.jwtConfig, token)
		if err != nil {
			writeUnauthorized(w, "Invalid or expired token")
			return
		}

		// 3. Hash Token for Lookup (NOT USED ANYMORE FOR DB LOOKUP, but kept for cache key transparency if needed)
		// tokenHash := security.HashToken(token)

		// 4. Check Cache (Use Session ID from claims)
		session, err := m.sessionCache.Get(r.Context(), claims.Sid)
		if err != nil || session == nil {
			// 5. Cache Miss -> Query DB
			dbSession, err := m.sessionRepo.FindByID(r.Context(), claims.Sid)
			if err != nil || dbSession == nil {
				writeUnauthorized(w, "Invalid session")
				return
			}
			session = &redis.CachedSession{
				SessionID:     dbSession.ID,
				UserID:        dbSession.UserID,
				MFAVerified:   dbSession.MFAVerified,
				ExpiresAt:     dbSession.ExpiresAt,
				IdleTimeoutAt: dbSession.IdleTimeoutAt,
			}
			if dbSession.TenantID != nil {
				session.TenantID = *dbSession.TenantID
			}
			// Cache the found session using Sid
			m.sessionCache.Set(r.Context(), claims.Sid, session)
		}

		// 6. Validate JWT claims against Session
		if claims.Sid != session.SessionID {
			writeUnauthorized(w, "Invalid session token")
			return
		}

		// 7. Validate Session Expiry
		if session.ExpiresAt.Before(time.Now()) {
			writeUnauthorized(w, "Session expired")
			return
		}

		// 7. Validate Idle Timeout
		if session.IdleTimeoutAt.Before(time.Now()) {
			m.sessionRepo.RevokeByID(r.Context(), session.SessionID, "idle_timeout", "system")
			m.sessionCache.Delete(r.Context(), session.SessionID)
			writeUnauthorized(w, "Session timed out due to inactivity")
			return
		}

		// 8. Debounced Activity Update
		// (Using a placeholder for last activity since it's not in CachedSession, 
		// or I should add it to CachedSession if needed. But let's use IdleTimeoutAt - 30min)
		lastActivity := session.IdleTimeoutAt.Add(-30 * time.Minute)
		if shouldUpdateActivity(lastActivity) {
			m.sessionRepo.UpdateActivity(r.Context(), session.SessionID)
			// Update local object and re-cache
			session.IdleTimeoutAt = time.Now().Add(30 * time.Minute)
			m.sessionCache.Set(r.Context(), session.SessionID, session)
		}

		// 9. Set Auth Context
		authCtx := &AuthContext{
			UserID:      session.UserID,
			SessionID:   session.SessionID,
			MFAVerified: session.MFAVerified,
			TokenHash:   "", // No longer using tokenHash for basic auth
			TenantID:    session.TenantID,
		}

		ctx := SetAuthContext(r.Context(), authCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (m *AuthMiddleware) HasPermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, err := GetAuthContext(r.Context())
			if err != nil {
				writeUnauthorized(w, "Unauthorized")
				return
			}

			if authCtx.TenantID == "" {
				writeForbidden(w, "No tenant context")
				return
			}

			permissions, err := m.membershipRepo.FindPermissionsByUserAndTenant(r.Context(), authCtx.UserID, authCtx.TenantID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Internal server error")
				return
			}

			hasPerm := false
			for _, p := range permissions {
				if matchPermission(p, permission) {
					hasPerm = true
					break
				}
			}

			if !hasPerm {
				writeForbidden(w, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func matchPermission(pattern, required string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == required {
		return true
	}
	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(required, prefix)
	}
	return false
}

func writeForbidden(w http.ResponseWriter, message string) {
	writeError(w, http.StatusForbidden, message)
}
