package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=repository
type UserRepository interface {
	Create(ctx context.Context, tx pgx.Tx, user *model.User) error
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
	SetVerified(ctx context.Context, tx pgx.Tx, userID string) error
	IncrementFailedLogin(ctx context.Context, userID string) (int, error)
	SuspendUser(ctx context.Context, userID string) error
	ResetFailedLoginAndUpdateLastLogin(ctx context.Context, userID string, ip string) error
}

type PostgresUserRepository struct {
	db *pgxpool.Pool
}

func NewPostgresUserRepository(db *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Create(ctx context.Context, tx pgx.Tx, user *model.User) error {
	query := `INSERT INTO users (email, username, is_active, is_verified) 
	          VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, query, user.Email, user.Username, user.IsActive, user.IsVerified).
			Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	} else {
		err = r.db.QueryRow(ctx, query, user.Email, user.Username, user.IsActive, user.IsVerified).
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
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.IsActive, &user.IsVerified, &user.IsSuspended, 
		&user.FailedLoginCount, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding user by email: %w", err)
	}
	return &user, nil
}

func (r *PostgresUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL)`
	err := r.db.QueryRow(ctx, query, email).Scan(&exists)
	return exists, err
}

func (r *PostgresUserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL)`
	err := r.db.QueryRow(ctx, query, username).Scan(&exists)
	return exists, err
}

func (r *PostgresUserRepository) SetVerified(ctx context.Context, tx pgx.Tx, userID string) error {
	query := `UPDATE users SET is_verified = true, updated_at = now() WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, userID)
	} else {
		_, err = r.db.Exec(ctx, query, userID)
	}
	if err != nil {
		return fmt.Errorf("error setting user as verified: %w", err)
	}
	return nil
}

func (r *PostgresUserRepository) IncrementFailedLogin(ctx context.Context, userID string) (int, error) {
	query := `UPDATE users SET failed_login_count = failed_login_count + 1, last_failed_login_at = now() 
	          WHERE id = $1 RETURNING failed_login_count`
	var count int
	err := r.db.QueryRow(ctx, query, userID).Scan(&count)
	return count, err
}

func (r *PostgresUserRepository) SuspendUser(ctx context.Context, userID string) error {
	query := `UPDATE users SET is_suspended = true, updated_at = now() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}

func (r *PostgresUserRepository) ResetFailedLoginAndUpdateLastLogin(ctx context.Context, userID string, ip string) error {
	query := `UPDATE users SET failed_login_count = 0, last_login_at = now(), last_login_ip = $1, updated_at = now() 
	          WHERE id = $2`
	_, err := r.db.Exec(ctx, query, ip, userID)
	return err
}

