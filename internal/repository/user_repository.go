package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

type UserRepository interface {
	Create(ctx context.Context, tx *sql.Tx, user *model.User) error
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
}

type PostgresUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Create(ctx context.Context, tx *sql.Tx, user *model.User) error {
	query := `INSERT INTO users (email, username, is_active, is_verified) 
	          VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, query, user.Email, user.Username, user.IsActive, user.IsVerified).
			Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	} else {
		err = r.db.QueryRowContext(ctx, query, user.Email, user.Username, user.IsActive, user.IsVerified).
			Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}
	return nil
}

func (r *PostgresUserRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, email, username, is_active, is_verified, is_suspended, failed_login_count, created_at, updated_at 
	          FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`
	
	var user model.User
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.IsActive, &user.IsVerified, &user.IsSuspended, 
		&user.FailedLoginCount, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding user by email: %w", err)
	}
	return &user, nil
}

func (r *PostgresUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL)`
	err := r.db.QueryRowContext(ctx, query, email).Scan(&exists)
	return exists, err
}

func (r *PostgresUserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL)`
	err := r.db.QueryRowContext(ctx, query, username).Scan(&exists)
	return exists, err
}
