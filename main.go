package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/herdifirdausss/auth/internal/handler"
	infraCache "github.com/herdifirdausss/auth/internal/infrastructure/cache"
	infraDB "github.com/herdifirdausss/auth/internal/infrastructure/database"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/infrastructure/telemetry"
	"github.com/herdifirdausss/auth/internal/logger"
	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/router"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/service"
)

func main() {
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	// 1. Initialize Logger
	l := logger.NewLogger(env)
	slog.SetDefault(l)

	// 2. Initialize Telemetry & Graceful Shutdown Context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tel.Shutdown(shutdownCtx); err != nil {
			slog.Error("Failed to shutdown telemetry", "error", err)
		}
	}()

	// 3. Database connection (pgxpool)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable"
	}
	db, err := infraDB.NewPostgresPool(ctx, dsn, l)
	if err != nil {
		slog.Error("Error connecting to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// 4. Redis connection
	redisClient, err := infraCache.NewRedisClient(ctx, "localhost", "6379", 0, l)
	if err != nil {
		slog.Error("Error connecting to redis", "error", err)
		os.Exit(1)
	}
	defer redisClient.Close()

	slog.Info("Infrastructure initialized successfully", "env", env)

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("randomjwtsecret"),
		AccessExpiry: 15 * time.Minute,
		Issuer:       "auth-service",
	}
	
	// Repositories
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
	
	// Services
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
		security.NewArgon2idHasher(), 
		redis.NewRateLimiter(redisClient), 
		redis.NewSessionCache(redisClient, time.Hour), 
		jwtConfig,
	)
	
	mfaService := service.NewMFAService(
		db, 
		mfaRepo, 
		userRepo, 
		sessionRepo, 
		refreshTokenRepo, 
		jwtConfig, 
		redis.NewRateLimiter(redisClient),
	)

	// Handlers
	authHandler := handler.NewAuthHandler(authService)
	authMiddleware := middleware.NewAuthMiddleware(jwtConfig, sessionRepo, redis.NewSessionCache(redisClient, time.Hour), tenantMembershipRepo)
	userHandler := handler.NewUserHandler()
	mfaHandler := handler.NewMFAHandler(mfaService)

	// Router
	r := router.NewRouter(authHandler, userHandler, mfaHandler, authMiddleware)

	// Wrap Router with Global Middlewares
	var h http.Handler = r
	h = middleware.RequestID(h)
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

	go func() {
		slog.Info("Starting server", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited gracefully")
}

