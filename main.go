package main

import (
	"fmt"
	"log"

	"github.com/herdifirdausss/auth/internal/database"
)

func main() {
	db, err := database.NewDB()
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	migrationPath := database.GetMigrationPath()
	fmt.Printf("Running migration from %s...\n", migrationPath)
	if err := database.RunMigration(db, migrationPath); err != nil {
		log.Fatalf("Error running migration: %v", err)
	}

	fmt.Println("Verifying migration...")
	if err := database.VerifyMigration(db); err != nil {
		log.Fatalf("Migration verification failed: %v", err)
	}

	fmt.Println("Migration successful and verified!")
}
