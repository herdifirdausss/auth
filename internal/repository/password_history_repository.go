package repository

import (
	"context"
	"fmt"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type PasswordHistoryRepository interface {
	GetRecentPasswords(ctx context.Context, userID string, limit int) ([]*model.UserPasswordHistory, error)
	Create(ctx context.Context, tx pgx.Tx, userID, passwordHash, passwordSalt string) error
	Cleanup(ctx context.Context, userID string, keepCount int) error
}

type PostgresPasswordHistoryRepository struct {
	db Pool
}

func NewPostgresPasswordHistoryRepository(db Pool) *PostgresPasswordHistoryRepository {
	return &PostgresPasswordHistoryRepository{db: db}
}

func (r *PostgresPasswordHistoryRepository) GetRecentPasswords(ctx context.Context, userID string, limit int) ([]*model.UserPasswordHistory, error) {
	query := `SELECT password_hash, password_salt FROM password_history 
	          WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`
	
	rows, err := r.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("error getting recent passwords: %w", err)
	}
	defer rows.Close()
	
	var history []*model.UserPasswordHistory
	for rows.Next() {
		var h model.UserPasswordHistory
		if err := rows.Scan(&h.PasswordHash, &h.PasswordSalt); err != nil {
			return nil, fmt.Errorf("error scanning password history: %w", err)
		}
		history = append(history, &h)
	}
	return history, nil
}

func (r *PostgresPasswordHistoryRepository) Create(ctx context.Context, tx pgx.Tx, userID, passwordHash, passwordSalt string) error {
	query := `INSERT INTO password_history (user_id, password_hash, password_salt) VALUES ($1, $2, $3)`
	
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, userID, passwordHash, passwordSalt)
	} else {
		_, err = r.db.Exec(ctx, query, userID, passwordHash, passwordSalt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating password history: %w", err)
	}
	return nil
}

func (r *PostgresPasswordHistoryRepository) Cleanup(ctx context.Context, userID string, keepCount int) error {
	query := `DELETE FROM password_history 
	          WHERE id IN (
	              SELECT id FROM password_history 
	              WHERE user_id = $1 
	              ORDER BY created_at DESC 
	              OFFSET $2
	          )`
	
	_, err := r.db.Exec(ctx, query, userID, keepCount)
	if err != nil {
		return fmt.Errorf("error cleaning up password history: %w", err)
	}
	return nil
}

