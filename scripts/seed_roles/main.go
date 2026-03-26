package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable"
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}
	defer conn.Close(ctx)

	seedSQL := `
	INSERT INTO roles (name, permissions, is_system) VALUES
	  ('super_admin', '["*"]',                                   true),
	  ('admin',       '["users:*","roles:*","audit:read"]',      true),
	  ('member',      '["profile:read","profile:update"]',       true),
	  ('guest',       '["profile:read"]',                        true)
	ON CONFLICT DO NOTHING;
	`

	_, err = conn.Exec(ctx, seedSQL)
	if err != nil {
		log.Fatalf("Error seeding roles: %v", err)
	}

	fmt.Println("Roles seeded successfully!")
}
