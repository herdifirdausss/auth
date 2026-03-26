package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/herdifirdausss/auth/internal/cron"
	"github.com/herdifirdausss/auth/internal/handler"
	infraCache "github.com/herdifirdausss/auth/internal/infrastructure/cache"
	infraDB "github.com/herdifirdausss/auth/internal/infrastructure/database"
	"github.com/herdifirdausss/auth/internal/infrastructure/metrics"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/infrastructure/telemetry"
	"github.com/herdifirdausss/auth/internal/logger"
	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/router"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/service"
	"github.com/herdifirdausss/auth/internal/utils"
)

func main() {
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	// 1. Initialize Context for Startup
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 2. Initialize Telemetry FIRST (AS PER REQUIREMENT)
	otelCfg := telemetry.Config{
		ServiceName:    "auth-service",
		ServiceVersion: "1.0.0",
		Environment:    env,
	}
	tel, err := telemetry.Setup(ctx, otelCfg)
	if err != nil {
		slog.Error("Failed to setup telemetry", "error", err)
		os.Exit(1)
	}

	// 3. Initialize Logger
	l := logger.NewLogger(env)
	slog.SetDefault(l)

	// 4. Initialize Prometheus Registry
	reg := metrics.NewRegistry()

	// 5. Infrastructure: Database (pgxpool with otelpgx)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
	}
	db, err := infraDB.NewPostgresPool(ctx, dsn, l)
	if err != nil {
		l.Error("Error connecting to database", "error", err)
		os.Exit(1)
	}

	// 6. Infrastructure: Redis (with redisotel)
	redisClient, err := infraCache.NewRedisClient(ctx, "localhost", "6379", 0, l)
	if err != nil {
		l.Error("Error connecting to redis", "error", err)
		os.Exit(1)
	}

	l.Info("Infrastructure initialized successfully", "env", env)

	// 7. Domain Configuration
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "this-is-a-very-secret-jwt-key-32-chars-long"
	}

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte(jwtSecret),
		AccessExpiry: 15 * time.Minute,
		Issuer:       "auth-service",
	}

	// 8. Repositories
	userRepo := repository.NewPostgresUserRepository(db)
	credRepo := repository.NewPostgresCredentialRepository(db)
	securityTokenRepo := repository.NewPostgresSecurityTokenRepository(db)
	securityEventRepo := repository.NewPostgresSecurityEventRepository(db)
	tenantRepo := repository.NewPostgresTenantRepository(db)
	tenantMembershipRepo := repository.NewPostgresTenantMembershipRepository(db)
	sessionRepo := repository.NewPostgresSessionRepository(db)
	refreshTokenRepo := repository.NewPostgresRefreshTokenRepository(db)
	mfaRepo := repository.NewPostgresMFARepository(db)
	passwordHistoryRepo := repository.NewPostgresPasswordHistoryRepository(db)
	roleRepo := repository.NewPostgresRoleRepository(db)
	membershipRoleRepo := repository.NewPostgresMembershipRoleRepository(db)
	trustedDeviceRepo := repository.NewPostgresTrustedDeviceRepository(db)
	auditLogRepo := repository.NewAuditLogRepository(db)

	auditService := service.NewAuditService(auditLogRepo)
	pwnedValidator := security.NewDefaultPwnedValidator()
	riskService := service.NewRiskService(userRepo, trustedDeviceRepo, l)
	permCache := redis.NewPermissionCache(redisClient, 15*time.Minute)

	// 9. Services (Injecting specialized logger)
	authService := service.NewAuthService(
		db,
		userRepo,
		credRepo,
		securityTokenRepo,
		securityEventRepo,
		tenantRepo,
		tenantMembershipRepo,
		sessionRepo,
		refreshTokenRepo,
		mfaRepo,
		passwordHistoryRepo,
		trustedDeviceRepo,
		roleRepo,
		membershipRoleRepo,
		riskService,
		pwnedValidator,
		auditService,
		security.NewArgon2idHasher(),
		redis.NewRateLimiter(redisClient),
		redis.NewSessionCache(redisClient, time.Hour),
		jwtConfig,
		l,
	)

	mfaService := service.NewMFAService(
		db,
		mfaRepo,
		userRepo,
		sessionRepo,
		refreshTokenRepo,
		tenantMembershipRepo,
		jwtConfig,
		redis.NewRateLimiter(redisClient),
		redis.NewSessionCache(redisClient, time.Hour),
		trustedDeviceRepo,
		utils.RealClock{},
		l,
	)

	tenantService := service.NewTenantService(
		db,
		userRepo,
		tenantMembershipRepo,
		tenantRepo,
		roleRepo,
		l,
	)

	permissionService := service.NewDefaultPermissionService(roleRepo, permCache)

	adminService := service.NewAdminService(tenantRepo, l)

	tenantAdminService := service.NewTenantAdminService(
		db,
		tenantRepo,
		tenantMembershipRepo,
		roleRepo,
		membershipRoleRepo,
		auditService,
	)

	webAuthnService, err := service.NewWebAuthnService(
		userRepo,
		mfaRepo,
		sessionRepo,
		refreshTokenRepo,
		tenantMembershipRepo,
		jwtConfig,
		redis.NewRateLimiter(redisClient),
		redis.NewSessionCache(redisClient, time.Hour),
		utils.RealClock{},
		l,
	)
	if err != nil {
		l.Error("Failed to initialize WebAuthn service", "error", err)
		os.Exit(1)
	}

	// 10. Background Workers (Cleanup Manager)
	cleanupManager := cron.NewCleanupManager(sessionRepo, refreshTokenRepo, 1*time.Hour, l)
	go cleanupManager.Start(ctx)

	// 11. Handlers
	authHandler := handler.NewAuthHandler(authService, l)
	authMiddleware := middleware.NewAuthMiddleware(jwtConfig, sessionRepo, redis.NewSessionCache(redisClient, time.Hour), tenantMembershipRepo)
	userHandler := handler.NewUserHandler()
	mfaHandler := handler.NewMFAHandler(mfaService, l)
	webAuthnHandler := handler.NewWebAuthnHandler(webAuthnService, l)
	adminHandler := handler.NewAdminHandler(adminService, l)
	tenantAdminHandler := handler.NewTenantAdminHandler(tenantAdminService, l)
	_ = tenantService // Reserved for future administrative handler

	// 12. Router & HTTP Server
	r := router.NewRouter(authHandler, userHandler, mfaHandler, webAuthnHandler, adminHandler, tenantAdminHandler, authMiddleware, permissionService, reg)

	// Wrap Router with Global Middlewares
	var h http.Handler = r
	h = middleware.RequestID(h)
	h = middleware.RequestLogger(h)
	h = middleware.SecurityHeaders(h)
	h = middleware.CORS(middleware.CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-Request-ID"},
	})(h)

	addr := ":8080"
	srv := &http.Server{
		Addr:    addr,
		Handler: h,
	}

	// 13. Start HTTP Server
	go func() {
		l.Info("Starting server", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			l.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	// 14. Graceful Shutdown Flow
	<-ctx.Done()
	l.Info("Shutdown signal received")

	// Order: telemetry -> scheduler -> httpServer

	// A. Telemetry Shutdown (Trace & Metric Providers)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l.Info("Shutting down telemetry...")
	if err := tel.Shutdown(shutdownCtx); err != nil {
		l.Error("Failed to shutdown telemetry", "error", err)
	}

	// B. Scheduler Shutdown
	l.Info("Stopping background workers...")
	cleanupManager.Stop()

	// C. HTTP Server Shutdown
	l.Info("Shutting down HTTP server...")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		l.Error("Server forced to shutdown", "error", err)
	}

	// D. Infrastructure Close
	l.Info("Closing infrastructure connections...")
	redisClient.Close()
	db.Close()

	l.Info("Server exited gracefully")
}
