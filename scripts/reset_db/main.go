package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5"
)

func main() {
	connStr := "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer conn.Close(ctx)

	tables := []string{
		"audit_logs",
		"security_events",
		"security_tokens",
		"sessions",
		"refresh_tokens",
		"mfa_recovery_codes",
		"mfa_methods",
		"password_history",
		"user_credentials",
		"tenant_memberships",
		"users",
		"tenants",
	}

	for _, table := range tables {
		_, err := conn.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE")
		if err != nil {
			log.Printf("Warning: failed to truncate %s: %v", table, err)
		}
	}
	log.Println("Database truncated successfully")
}
