package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

type MFARepository interface {
	FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error)
	Create(ctx context.Context, method *model.MFAMethod) error
	FindInactiveByUser(ctx context.Context, userID, methodType string) (*model.MFAMethod, error)
	Activate(ctx context.Context, id string) error
	SetBackupCodes(ctx context.Context, id, encrypted string) error
}

type PostgresMFARepository struct {
	db *sql.DB
}

func NewPostgresMFARepository(db *sql.DB) *PostgresMFARepository {
	return &PostgresMFARepository{db: db}
}

func (r *PostgresMFARepository) FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error) {
	query := `SELECT id, user_id, method_type, method_name, secret_encrypted, 
	          backup_codes_encrypted, is_active, is_primary, last_used_at, created_at, updated_at 
	          FROM mfa_methods WHERE user_id = $1 AND is_active = true AND is_primary = true`
	
	var m model.MFAMethod
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&m.ID, &m.UserID, &m.MethodType, &m.MethodName, &m.SecretEncrypted,
		&m.BackupCodesEncrypted, &m.IsActive, &m.IsPrimary, &m.LastUsedAt, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding primary MFA method: %w", err)
	}
	return &m, nil
}

func (r *PostgresMFARepository) Create(ctx context.Context, method *model.MFAMethod) error {
	query := `INSERT INTO mfa_methods (user_id, method_type, method_name, secret_encrypted, is_active, is_primary) 
	          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at, updated_at`
	
	return r.db.QueryRowContext(ctx, query, method.UserID, method.MethodType, method.MethodName, 
		method.SecretEncrypted, method.IsActive, method.IsPrimary).
		Scan(&method.ID, &method.CreatedAt, &method.UpdatedAt)
}

func (r *PostgresMFARepository) FindInactiveByUser(ctx context.Context, userID, methodType string) (*model.MFAMethod, error) {
	query := `SELECT id, user_id, method_type, method_name, secret_encrypted, 
	          backup_codes_encrypted, is_active, is_primary, last_used_at, created_at, updated_at 
	          FROM mfa_methods WHERE user_id = $1 AND method_type = $2 AND is_active = false`
	
	var m model.MFAMethod
	err := r.db.QueryRowContext(ctx, query, userID, methodType).Scan(
		&m.ID, &m.UserID, &m.MethodType, &m.MethodName, &m.SecretEncrypted,
		&m.BackupCodesEncrypted, &m.IsActive, &m.IsPrimary, &m.LastUsedAt, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding inactive MFA method: %w", err)
	}
	return &m, nil
}

func (r *PostgresMFARepository) Activate(ctx context.Context, id string) error {
	query := `UPDATE mfa_methods SET is_active = true, is_primary = true WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *PostgresMFARepository) SetBackupCodes(ctx context.Context, id, encrypted string) error {
	query := `UPDATE mfa_methods SET backup_codes_encrypted = $2 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, encrypted)
	return err
}
