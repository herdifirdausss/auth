package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

func main() {
	// 1. Redis
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	err := rdb.FlushDB(context.Background()).Err()
	if err != nil {
		log.Printf("Warning: failed to flush redis: %v", err)
	} else {
		fmt.Println("Redis flushed.")
	}

	// 2. Database
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
	}

	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer conn.Close(context.Background())

	// Create test-tenant if not exists
	_, err = conn.Exec(context.Background(), 
		"INSERT INTO tenants (name, slug) VALUES ('Test Tenant', 'test-tenant') ON CONFLICT DO NOTHING")
	if err != nil {
		log.Fatalf("Error creating tenant: %v", err)
	}

	// Fix missing user_agent column (if not already there)
	_, err = conn.Exec(context.Background(), "ALTER TABLE security_tokens ADD COLUMN IF NOT EXISTS user_agent text")
	if err != nil {
		log.Fatalf("Error adding user_agent column: %v", err)
	}

	fmt.Println("Test tenant 'test-tenant' ready.")
}
