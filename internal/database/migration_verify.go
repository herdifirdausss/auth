package database

import (
	"database/sql"
	"fmt"
)

func VerifyMigration(db *sql.DB) error {
	tables := []string{
		"users", "user_credentials", "password_history", "tenants",
		"tenant_memberships", "roles", "membership_roles", "sessions",
		"refresh_tokens", "security_tokens", "mfa_methods", "trusted_devices",
		"security_events", "audit_logs",
	}

	for _, table := range tables {
		var exists bool
		query := `SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE  table_schema = 'public'
			AND    table_name   = $1
		);`
		err := db.QueryRow(query, table).Scan(&exists)
		if err != nil {
			return fmt.Errorf("error checking existence of table %s: %w", table, err)
		}
		if !exists {
			return fmt.Errorf("table %s does not exist", table)
		}
	}
	if err := VerifyRoles(db); err != nil {
		return err
	}

	return nil
}

func VerifyRoles(db *sql.DB) error {
	roles := []string{"super_admin", "admin", "member", "guest"}
	for _, role := range roles {
		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)", role).Scan(&exists)
		if err != nil {
			return fmt.Errorf("error checking role %s: %w", role, err)
		}
		if !exists {
			return fmt.Errorf("role %s does not exist", role)
		}
	}
	return nil
}
