package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run scripts/grant_admin/main.go <email>")
	}
	email := os.Args[1]

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

	// 1. Find User ID
	var userID string
	err = conn.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
	if err != nil {
		log.Fatalf("User not found: %v", err)
	}

	// 2. Find Super Admin Role ID
	var roleID string
	err = conn.QueryRow(ctx, "SELECT id FROM roles WHERE name = 'super_admin' AND is_system = true").Scan(&roleID)
	if err != nil {
		log.Fatalf("Super Admin role not found: %v", err)
	}

	// 3. Find Membership(s)
	rows, err := conn.Query(ctx, "SELECT id FROM tenant_memberships WHERE user_id = $1", userID)
	if err != nil {
		log.Fatalf("Error finding memberships: %v", err)
	}
	defer rows.Close()

	var membershipIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			log.Fatalf("Error scanning membership ID: %v", err)
		}
		membershipIDs = append(membershipIDs, id)
	}

	if len(membershipIDs) == 0 {
		log.Fatal("User has no memberships")
	}

	// 4. Grant Role
	for _, mID := range membershipIDs {
		_, err = conn.Exec(ctx, "INSERT INTO membership_roles (membership_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", mID, roleID)
		if err != nil {
			log.Fatalf("Error granting role for membership %s: %v", mID, err)
		}
	}

	fmt.Printf("Successfully granted super_admin role to %s\n", email)
}
