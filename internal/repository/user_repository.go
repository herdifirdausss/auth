package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type UserRepository interface {
	FindByID(ctx context.Context, id string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	Create(ctx context.Context, tx pgx.Tx, user *model.User) error
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	ExistsByUsername(ctx context.Context, username string) (bool, error)
	SetVerified(ctx context.Context, tx pgx.Tx, userID string) error
	UpdatePasswordChangedAt(ctx context.Context, tx pgx.Tx, userID string) error
	UpdateLastLogin(ctx context.Context, userID string, ip string) error
	IncrementFailedLogin(ctx context.Context, userID string) (int, error)
	ResetFailedLogin(ctx context.Context, userID string) error
	Suspend(ctx context.Context, userID string) error
	SoftDelete(ctx context.Context, userID string) error
}

type PostgresUserRepository struct {
	db Pool
}

func NewPostgresUserRepository(db Pool) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Create(ctx context.Context, tx pgx.Tx, user *model.User) error {
	query := `INSERT INTO users (email, username, phone, is_active, is_verified, metadata) 
	          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at, updated_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, query, user.Email, user.Username, user.Phone, user.IsActive, user.IsVerified, user.Metadata).
			Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	} else {
		err = r.db.QueryRow(ctx, query, user.Email, user.Username, user.Phone, user.IsActive, user.IsVerified, user.Metadata).
			Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}
	return nil
}

func (r *PostgresUserRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, email, username, phone, is_active, is_verified, is_suspended, 
	          failed_login_count, last_login_at, last_login_ip::text, password_changed_at, metadata, created_at, updated_at 
	          FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`
	
	var user model.User
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.Phone, &user.IsActive, &user.IsVerified, &user.IsSuspended, 
		&user.FailedLoginCount, &user.LastLoginAt, &user.LastLoginIP, &user.PasswordChangedAt, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding user by email: %w", err)
	}
	return &user, nil
}

func (r *PostgresUserRepository) FindByID(ctx context.Context, id string) (*model.User, error) {
	query := `SELECT id, email, username, phone, is_active, is_verified, is_suspended, 
	          failed_login_count, last_login_at, last_login_ip::text, password_changed_at, metadata, created_at, updated_at 
	          FROM users WHERE id = $1 AND deleted_at IS NULL`
	
	var user model.User
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Username, &user.Phone, &user.IsActive, &user.IsVerified, &user.IsSuspended, 
		&user.FailedLoginCount, &user.LastLoginAt, &user.LastLoginIP, &user.PasswordChangedAt, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding user by id: %w", err)
	}
	return &user, nil
}

func (r *PostgresUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL)`
	var exists bool
	err := r.db.QueryRow(ctx, query, email).Scan(&exists)
	return exists, err
}

func (r *PostgresUserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL)`
	var exists bool
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
	return err
}

func (r *PostgresUserRepository) UpdatePasswordChangedAt(ctx context.Context, tx pgx.Tx, userID string) error {
	query := `UPDATE users SET password_changed_at = now(), updated_at = now() WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, userID)
	} else {
		_, err = r.db.Exec(ctx, query, userID)
	}
	return err
}

func (r *PostgresUserRepository) UpdateLastLogin(ctx context.Context, userID string, ip string) error {
	query := `UPDATE users SET last_login_at = now(), last_login_ip = $1, failed_login_count = 0, updated_at = now() WHERE id = $2`
	_, err := r.db.Exec(ctx, query, ip, userID)
	return err
}

func (r *PostgresUserRepository) IncrementFailedLogin(ctx context.Context, userID string) (int, error) {
	query := `UPDATE users SET failed_login_count = failed_login_count + 1, updated_at = now() WHERE id = $1 RETURNING failed_login_count`
	var count int
	err := r.db.QueryRow(ctx, query, userID).Scan(&count)
	return count, err
}

func (r *PostgresUserRepository) ResetFailedLogin(ctx context.Context, userID string) error {
	query := `UPDATE users SET failed_login_count = 0, updated_at = now() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}

func (r *PostgresUserRepository) Suspend(ctx context.Context, userID string) error {
	query := `UPDATE users SET is_suspended = true, updated_at = now() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}

func (r *PostgresUserRepository) SoftDelete(ctx context.Context, userID string) error {
	query := `UPDATE users SET deleted_at = now(), updated_at = now(), is_active = false WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}
