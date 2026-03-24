package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/herdifirdausss/auth/internal/config"
	"github.com/herdifirdausss/auth/internal/database"
	"github.com/herdifirdausss/auth/internal/handler"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/router"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/service"
)

func main() {
	db, err := database.NewDB()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	// migrationPath := database.GetMigrationPath()
	// fmt.Printf("Running migration from %s...\n", migrationPath)
	// if err := database.RunMigration(db, migrationPath); err != nil {
	// 	log.Fatalf("Error running migration: %v", err)
	// }

	// fmt.Println("Verifying migration...")
	// if err := database.VerifyMigration(db); err != nil {
	// 	log.Fatalf("Migration verification failed: %v", err)
	// }

	redisClient, err := redis.NewRedisClient(config.RedisConfig{
		Host: "localhost",
		Port: "6379",
	})
	if err != nil {
		log.Fatalf("Error connecting to redis: %v", err)
	}

	fmt.Println("Migration successful and verified!")

	jwtConfig := security.JWTConfig{
		SecretKey:    []byte("randomjwtsecret"),
		AccessExpiry: 15 * time.Minute,
		Issuer:       "auth-service",
	}
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
	authService := service.NewAuthService(db, userRepo, credRepo, securityTokenRepo, securityEventRepo, tenantRepo, tenantMembershipRepo, sessionRepo, refreshTokenRepo, mfaRepo, passwordHistoryRepo, security.NewArgon2idHasher(), redis.NewRateLimiter(redisClient), redis.NewSessionCache(redisClient, time.Hour), jwtConfig)
	mfaService := service.NewMFAService(db, mfaRepo, userRepo, sessionRepo, refreshTokenRepo, jwtConfig, redis.NewRateLimiter(redisClient))

	authHandler := handler.NewAuthHandler(authService)
	authMiddleware := middleware.NewAuthMiddleware(jwtConfig, sessionRepo, redis.NewSessionCache(redisClient, time.Hour), tenantMembershipRepo)
	userHandler := handler.NewUserHandler()
	mfaHandler := handler.NewMFAHandler(mfaService)

	r := router.NewRouter(authHandler, userHandler, mfaHandler, authMiddleware)
	addr := ":8080"
	fmt.Printf("Starting server at %s...\n", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
