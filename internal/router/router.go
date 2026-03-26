package router

import (
	"net/http"
	"strings"
	"github.com/herdifirdausss/auth/internal/handler"
	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/service"
	"github.com/herdifirdausss/auth/internal/infrastructure/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func NewRouter(
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	mfaHandler *handler.MFAHandler,
	webAuthnHandler *handler.WebAuthnHandler,
	adminHandler *handler.AdminHandler,
	tenantAdminHandler *handler.TenantAdminHandler,
	authMiddleware *middleware.AuthMiddleware,
	permService service.PermissionService,
	reg *prometheus.Registry,
) *http.ServeMux {
	mux := http.NewServeMux()

	// Metrics
	mux.Handle("/metrics", metrics.Handler(reg))

	// Public Routes
	mux.HandleFunc("/auth/register", authHandler.Register)
	mux.HandleFunc("/auth/verify-email", authHandler.VerifyEmail)
	mux.HandleFunc("/auth/login", authHandler.Login)
	mux.HandleFunc("/auth/token/refresh", authHandler.RefreshToken)
	mux.HandleFunc("/auth/forgot-password", authHandler.ForgotPassword)
	mux.HandleFunc("/auth/reset-password", authHandler.ResetPassword)
	mux.HandleFunc("/auth/mfa/challenge", mfaHandler.Challenge)

	// WebAuthn Public Routes
	mux.HandleFunc("/auth/mfa/webauthn/login/begin", webAuthnHandler.BeginLogin)
	mux.HandleFunc("/auth/mfa/webauthn/login/finish", webAuthnHandler.FinishLogin)

	// Protected Routes
	mux.Handle("/auth/me", authMiddleware.Authenticate(http.HandlerFunc(userHandler.Me)))
	mux.Handle("/auth/mfa/setup", authMiddleware.Authenticate(http.HandlerFunc(mfaHandler.Setup)))
	mux.Handle("/auth/mfa/verify-setup", authMiddleware.Authenticate(http.HandlerFunc(mfaHandler.VerifySetup)))
	mux.Handle("/auth/mfa/disable", authMiddleware.Authenticate(http.HandlerFunc(mfaHandler.Disable)))
	mux.Handle("/auth/logout", authMiddleware.Authenticate(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("/auth/logout-all", authMiddleware.Authenticate(http.HandlerFunc(authHandler.LogoutAll)))

	mux.Handle("/auth/mfa/webauthn/register/begin", authMiddleware.Authenticate(http.HandlerFunc(webAuthnHandler.BeginRegistration)))
	mux.Handle("/auth/mfa/webauthn/register/finish", authMiddleware.Authenticate(http.HandlerFunc(webAuthnHandler.FinishRegistration)))

	// Admin Routes (Super Admin Only)
	mux.Handle("/admin/tenants", authMiddleware.Authenticate(middleware.RequireRole(permService, "super_admin")(http.HandlerFunc(adminHandler.ListTenants))))
	mux.Handle("/admin/tenants/status", authMiddleware.Authenticate(middleware.RequireRole(permService, "super_admin")(http.HandlerFunc(adminHandler.UpdateTenantStatus))))

	// Tenant Admin Routes
	mux.Handle("/admin/tenant/settings", authMiddleware.Authenticate(middleware.RequireRole(permService, "admin")(http.HandlerFunc(tenantAdminHandler.GetSettings))))
	mux.Handle("/admin/tenant/settings/update", authMiddleware.Authenticate(middleware.RequireRole(permService, "admin")(http.HandlerFunc(tenantAdminHandler.UpdateSettings))))
	
	mux.Handle("/admin/tenant/roles", authMiddleware.Authenticate(middleware.RequireRole(permService, "admin")(http.HandlerFunc(tenantAdminHandler.ListRoles))))
	mux.Handle("/admin/tenant/roles/create", authMiddleware.Authenticate(middleware.RequireRole(permService, "admin")(http.HandlerFunc(tenantAdminHandler.CreateRole))))
	
	mux.Handle("/admin/tenant/members", authMiddleware.Authenticate(middleware.RequireRole(permService, "admin")(http.HandlerFunc(tenantAdminHandler.ListMembers))))
	
	// Complex routes with IDs
	mux.Handle("/admin/tenant/roles/", authMiddleware.Authenticate(middleware.RequireRole(permService, "admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			tenantAdminHandler.UpdateRole(w, r)
		} else if r.Method == http.MethodDelete {
			tenantAdminHandler.DeleteRole(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))))

	mux.Handle("/admin/tenant/members/", authMiddleware.Authenticate(middleware.RequireRole(permService, "admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/roles") {
			tenantAdminHandler.UpdateMemberRoles(w, r)
			return
		}
		if r.Method == http.MethodPatch {
			tenantAdminHandler.UpdateMember(w, r)
		} else if r.Method == http.MethodDelete {
			tenantAdminHandler.RemoveMember(w, r)
		} else {
			http.NotFound(w, r)
		}
	}))))

	return mux
}
