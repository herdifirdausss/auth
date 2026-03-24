package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
)

func RunMigration(db *sql.DB, migrationPath string) error {
	content, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("error reading migration file: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}

	defer tx.Rollback()

	_, err = tx.Exec(string(content))
	if err != nil {
		return fmt.Errorf("error executing migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

func GetMigrationPath() string {
	// Assuming migrations are in the root directory 'migrations'
	return filepath.Join("migrations", "001_auth_mvp_schema.sql")
}
