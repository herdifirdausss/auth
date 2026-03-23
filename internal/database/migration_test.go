package database

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRunMigration_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(".*").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Use a dummy path for testing
	err = RunMigrationWithContent(db, "CREATE TABLE test (id INT);")
	if err != nil {
		t.Errorf("error was not expected while running migration: %s", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

// Add a helper for testing
func RunMigrationWithContent(db *sql.DB, content string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(content)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func TestVerifyMigration_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	tables := []string{
		"users", "user_credentials", "password_history", "tenants",
		"tenant_memberships", "roles", "membership_roles", "sessions",
		"refresh_tokens", "security_tokens", "mfa_methods", "trusted_devices",
		"security_events", "audit_logs",
	}

	for range tables {
		mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	}

	// Roles expectations
	roles := []string{"super_admin", "admin", "member", "guest"}
	for range roles {
		mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	}

	err = VerifyMigration(db)
	if err != nil {
		t.Errorf("error was not expected while verifying migration: %s", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestVerifyMigration_TableMissing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	err = VerifyMigration(db)
	if err == nil {
		t.Errorf("expected error when table is missing, but got nil")
	}
}

func TestVerifyMigration_RoleMissing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	tables := make([]string, 14)
	for range tables {
		mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	}

	mock.ExpectQuery("SELECT EXISTS").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	err = VerifyMigration(db)
	if err == nil {
		t.Errorf("expected error when role is missing, but got nil")
	}
}

func TestRunMigration_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mock.ExpectBegin().WillReturnError(fmt.Errorf("begin error"))

	err = RunMigrationWithContent(db, "CREATE TABLE test (id INT);")
	if err == nil {
		t.Errorf("expected error on begin, but got nil")
	}
}
