package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

type MFARepository interface {
	FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error)
}

type PostgresMFARepository struct {
	db *sql.DB
}

func NewPostgresMFARepository(db *sql.DB) *PostgresMFARepository {
	return &PostgresMFARepository{db: db}
}

func (r *PostgresMFARepository) FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error) {
	query := `SELECT id, user_id, method_type, method_name, is_active, is_primary, created_at FROM mfa_methods 
	          WHERE user_id = $1 AND is_active = true AND is_primary = true LIMIT 1`
	
	var m model.MFAMethod
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&m.ID, &m.UserID, &m.MethodType, &m.MethodName, &m.IsActive, &m.IsPrimary, &m.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding primary mfa: %w", err)
	}
	return &m, nil
}
