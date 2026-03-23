package repository

import (
	"context"
	"database/sql"
	"fmt"
)

type PasswordHistoryRepository interface {
	GetRecentPasswords(ctx context.Context, userID string, limit int) ([]string, error)
	Create(ctx context.Context, tx *sql.Tx, userID, passwordHash string) error
	Cleanup(ctx context.Context, userID string, keepCount int) error
}

type PostgresPasswordHistoryRepository struct {
	db *sql.DB
}

func NewPostgresPasswordHistoryRepository(db *sql.DB) *PostgresPasswordHistoryRepository {
	return &PostgresPasswordHistoryRepository{db: db}
}

func (r *PostgresPasswordHistoryRepository) GetRecentPasswords(ctx context.Context, userID string, limit int) ([]string, error) {
	query := `SELECT password_hash FROM user_password_history 
	          WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`
	
	rows, err := r.db.QueryContext(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("error getting recent passwords: %w", err)
	}
	defer rows.Close()
	
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("error scanning password hash: %w", err)
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

func (r *PostgresPasswordHistoryRepository) Create(ctx context.Context, tx *sql.Tx, userID, passwordHash string) error {
	query := `INSERT INTO user_password_history (user_id, password_hash) VALUES ($1, $2)`
	
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID, passwordHash)
	} else {
		_, err = r.db.ExecContext(ctx, query, userID, passwordHash)
	}
	
	if err != nil {
		return fmt.Errorf("error creating password history: %w", err)
	}
	return nil
}

func (r *PostgresPasswordHistoryRepository) Cleanup(ctx context.Context, userID string, keepCount int) error {
	query := `DELETE FROM user_password_history 
	          WHERE id IN (
	              SELECT id FROM user_password_history 
	              WHERE user_id = $1 
	              ORDER BY created_at DESC 
	              OFFSET $2
	          )`
	
	_, err := r.db.ExecContext(ctx, query, userID, keepCount)
	if err != nil {
		return fmt.Errorf("error cleaning up password history: %w", err)
	}
	return nil
}
