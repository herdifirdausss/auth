package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type MFARepository interface {
	FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error)
	Create(ctx context.Context, method *model.MFAMethod) error
	FindInactiveByUser(ctx context.Context, userID, methodType string) (*model.MFAMethod, error)
	Activate(ctx context.Context, tx pgx.Tx, id string) error
	DeactivateAll(ctx context.Context, userID string) error
	SetBackupCodes(ctx context.Context, tx pgx.Tx, id, encrypted string) error
	IncrementUseCount(ctx context.Context, tx pgx.Tx, id string) error
	FindAllByUserIDAndType(ctx context.Context, userID, methodType string) ([]*model.MFAMethod, error)
}

type PostgresMFARepository struct {
	db Pool
}

func NewPostgresMFARepository(db Pool) *PostgresMFARepository {
	return &PostgresMFARepository{db: db}
}

func (r *PostgresMFARepository) FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error) {
	query := `SELECT id, user_id, method_type, method_name, secret_encrypted, 
	          COALESCE(backup_codes_encrypted, ''), credential_id, public_key, 
	          is_active, is_primary, last_used_at, use_count, created_at, updated_at 
	          FROM mfa_methods WHERE user_id = $1 AND is_active = true AND is_primary = true`
	
	var m model.MFAMethod
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&m.ID, &m.UserID, &m.MethodType, &m.MethodName, &m.SecretEncrypted,
		&m.BackupCodesEncrypted, &m.CredentialID, &m.PublicKey,
		&m.IsActive, &m.IsPrimary, &m.LastUsedAt, &m.UseCount, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding primary MFA method: %w", err)
	}
	return &m, nil
}

func (r *PostgresMFARepository) Create(ctx context.Context, method *model.MFAMethod) error {
	query := `INSERT INTO mfa_methods (
				user_id, method_type, method_name, secret_encrypted, 
				credential_id, public_key, is_active, is_primary
			  ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
			  RETURNING id, created_at, updated_at`
	
	return r.db.QueryRow(ctx, query, 
		method.UserID, method.MethodType, method.MethodName, method.SecretEncrypted,
		method.CredentialID, method.PublicKey, method.IsActive, method.IsPrimary).
		Scan(&method.ID, &method.CreatedAt, &method.UpdatedAt)
}

func (r *PostgresMFARepository) FindInactiveByUser(ctx context.Context, userID, methodType string) (*model.MFAMethod, error) {
	query := `SELECT id, user_id, method_type, method_name, secret_encrypted, 
	          COALESCE(backup_codes_encrypted, ''), credential_id, public_key, 
	          is_active, is_primary, last_used_at, use_count, created_at, updated_at 
	          FROM mfa_methods WHERE user_id = $1 AND method_type = $2 AND is_active = false`
	
	var m model.MFAMethod
	err := r.db.QueryRow(ctx, query, userID, methodType).Scan(
		&m.ID, &m.UserID, &m.MethodType, &m.MethodName, &m.SecretEncrypted,
		&m.BackupCodesEncrypted, &m.CredentialID, &m.PublicKey,
		&m.IsActive, &m.IsPrimary, &m.LastUsedAt, &m.UseCount, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding inactive MFA method: %w", err)
	}
	return &m, nil
}

func (r *PostgresMFARepository) Activate(ctx context.Context, tx pgx.Tx, id string) error {
	query := `UPDATE mfa_methods SET is_active = true, is_primary = true WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, id)
	} else {
		_, err = r.db.Exec(ctx, query, id)
	}
	return err
}

func (r *PostgresMFARepository) DeactivateAll(ctx context.Context, userID string) error {
	query := `UPDATE mfa_methods SET is_active = false, is_primary = false WHERE user_id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}

func (r *PostgresMFARepository) SetBackupCodes(ctx context.Context, tx pgx.Tx, id, encrypted string) error {
	query := `UPDATE mfa_methods SET backup_codes_encrypted = $2 WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, id, encrypted)
	} else {
		_, err = r.db.Exec(ctx, query, id, encrypted)
	}
	return err
}

func (r *PostgresMFARepository) IncrementUseCount(ctx context.Context, tx pgx.Tx, id string) error {
	query := `UPDATE mfa_methods SET use_count = use_count + 1, last_used_at = now() WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, id)
	} else {
		_, err = r.db.Exec(ctx, query, id)
	}
	return err
}

func (r *PostgresMFARepository) FindAllByUserIDAndType(ctx context.Context, userID, methodType string) ([]*model.MFAMethod, error) {
	query := `SELECT id, user_id, method_type, method_name, secret_encrypted, 
	          COALESCE(backup_codes_encrypted, ''), credential_id, public_key, 
	          is_active, is_primary, last_used_at, use_count, created_at, updated_at 
	          FROM mfa_methods WHERE user_id = $1 AND method_type = $2 AND is_active = true`
	
	rows, err := r.db.Query(ctx, query, userID, methodType)
	if err != nil {
		return nil, fmt.Errorf("error querying MFA methods: %w", err)
	}
	defer rows.Close()

	var methods []*model.MFAMethod
	for rows.Next() {
		var m model.MFAMethod
		err := rows.Scan(
			&m.ID, &m.UserID, &m.MethodType, &m.MethodName, &m.SecretEncrypted,
			&m.BackupCodesEncrypted, &m.CredentialID, &m.PublicKey,
			&m.IsActive, &m.IsPrimary, &m.LastUsedAt, &m.UseCount, &m.CreatedAt, &m.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning MFA method: %w", err)
		}
		methods = append(methods, &m)
	}
	return methods, nil
}
