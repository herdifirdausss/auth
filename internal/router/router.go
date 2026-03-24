package router

import (
	"net/http"
	"github.com/herdifirdausss/auth/internal/handler"
	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/infrastructure/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func NewRouter(authHandler *handler.AuthHandler, userHandler *handler.UserHandler, mfaHandler *handler.MFAHandler, authMiddleware *middleware.AuthMiddleware, reg *prometheus.Registry) *http.ServeMux {
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

	// Protected Routes
	mux.Handle("/auth/me", authMiddleware.Authenticate(http.HandlerFunc(userHandler.Me)))
	mux.Handle("/auth/mfa/setup", authMiddleware.Authenticate(http.HandlerFunc(mfaHandler.Setup)))
	mux.Handle("/auth/mfa/verify-setup", authMiddleware.Authenticate(http.HandlerFunc(mfaHandler.VerifySetup)))
	mux.Handle("/auth/logout", authMiddleware.Authenticate(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("/auth/logout-all", authMiddleware.Authenticate(http.HandlerFunc(authHandler.LogoutAll)))

	return mux
}
