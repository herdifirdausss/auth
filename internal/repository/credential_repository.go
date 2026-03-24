package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type CredentialRepository interface {
	Create(ctx context.Context, tx pgx.Tx, cred *model.UserCredential) error
	FindByUserID(ctx context.Context, userID string) (*model.UserCredential, error)
	UpdatePassword(ctx context.Context, tx pgx.Tx, userID, hash, salt string) error
}

type PostgresCredentialRepository struct {
	db Pool
}

func NewPostgresCredentialRepository(db Pool) *PostgresCredentialRepository {
	return &PostgresCredentialRepository{db: db}
}

func (r *PostgresCredentialRepository) Create(ctx context.Context, tx pgx.Tx, cred *model.UserCredential) error {
	query := `INSERT INTO user_credentials (user_id, password_hash, password_salt, password_algo) 
	          VALUES ($1, $2, $3, $4) RETURNING created_at, updated_at`

	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, query, cred.UserID, cred.PasswordHash, cred.PasswordSalt, cred.PasswordAlgo).
			Scan(&cred.CreatedAt, &cred.UpdatedAt)
	} else {
		err = r.db.QueryRow(ctx, query, cred.UserID, cred.PasswordHash, cred.PasswordSalt, cred.PasswordAlgo).
			Scan(&cred.CreatedAt, &cred.UpdatedAt)
	}

	if err != nil {
		return fmt.Errorf("error creating credential: %w", err)
	}
	return nil
}

func (r *PostgresCredentialRepository) FindByUserID(ctx context.Context, userID string) (*model.UserCredential, error) {
	query := `SELECT user_id, password_hash, password_salt, password_algo, must_change_password, last_changed_at, created_at, updated_at 
	          FROM user_credentials WHERE user_id = $1`

	var cred model.UserCredential
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&cred.UserID, &cred.PasswordHash, &cred.PasswordSalt, &cred.PasswordAlgo,
		&cred.MustChangePassword, &cred.LastChangedAt, &cred.CreatedAt, &cred.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding credential by user id: %w", err)
	}
	return &cred, nil
}

func (r *PostgresCredentialRepository) UpdatePassword(ctx context.Context, tx pgx.Tx, userID, hash, salt string) error {
	query := `UPDATE user_credentials 
	          SET password_hash = $2, password_salt = $3, last_changed_at = now(), change_count = change_count + 1 
	          WHERE user_id = $1`

	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, userID, hash, salt)
	} else {
		_, err = r.db.Exec(ctx, query, userID, hash, salt)
	}

	if err != nil {
		return fmt.Errorf("error updating password: %w", err)
	}
	return nil
}

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type SecurityTokenRepository interface {
	Create(ctx context.Context, token *model.SecurityToken) error
	FindValidToken(ctx context.Context, tokenHash string, tokenType string) (*model.SecurityToken, error)
	MarkUsed(ctx context.Context, tx pgx.Tx, tokenID string) error
}

type PostgresSecurityTokenRepository struct {
	db Pool
}

func NewPostgresSecurityTokenRepository(db Pool) *PostgresSecurityTokenRepository {
	return &PostgresSecurityTokenRepository{db: db}
}

func (r *PostgresSecurityTokenRepository) Create(ctx context.Context, token *model.SecurityToken) error {
	query := `INSERT INTO security_tokens (user_id, token_type, token_hash, expires_at, ip_address, user_agent) 
	          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`

	err := r.db.QueryRow(ctx, query, token.UserID, token.TokenType, token.TokenHash, token.ExpiresAt, token.IPAddress, token.UserAgent).
		Scan(&token.ID, &token.CreatedAt)

	if err != nil {
		return fmt.Errorf("error creating security token: %w", err)
	}
	return nil
}

func (r *PostgresSecurityTokenRepository) FindValidToken(ctx context.Context, tokenHash string, tokenType string) (*model.SecurityToken, error) {
	query := `SELECT id, user_id, token_type, token_hash, expires_at, used_at, ip_address::text, user_agent, created_at 
	          FROM security_tokens 
	          WHERE token_hash = $1 AND token_type = $2 AND used_at IS NULL AND expires_at > now()`

	var token model.SecurityToken
	err := r.db.QueryRow(ctx, query, tokenHash, tokenType).Scan(
		&token.ID, &token.UserID, &token.TokenType, &token.TokenHash, &token.ExpiresAt, &token.UsedAt,
		&token.IPAddress, &token.UserAgent, &token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding valid token: %w", err)
	}
	return &token, nil
}

func (r *PostgresSecurityTokenRepository) MarkUsed(ctx context.Context, tx pgx.Tx, tokenID string) error {
	query := `UPDATE security_tokens SET used_at = now() WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, tokenID)
	} else {
		_, err = r.db.Exec(ctx, query, tokenID)
	}
	if err != nil {
		return fmt.Errorf("error marking token as used: %w", err)
	}
	return nil
}

// directive for the whole file is already at the top
type SecurityEventRepository interface {
	Create(ctx context.Context, event *model.SecurityEvent) error
}

type PostgresSecurityEventRepository struct {
	db Pool
}

func NewPostgresSecurityEventRepository(db Pool) *PostgresSecurityEventRepository {
	return &PostgresSecurityEventRepository{db: db}
}

func (r *PostgresSecurityEventRepository) Create(ctx context.Context, event *model.SecurityEvent) error {
	query := `INSERT INTO security_events (user_id, tenant_id, event_type, severity, details, ip_address, user_agent) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at`

	err := r.db.QueryRow(ctx, query, event.UserID, event.TenantID, event.EventType, event.Severity, event.Details, event.IPAddress, event.UserAgent).
		Scan(&event.ID, &event.CreatedAt)

	if err != nil {
		return fmt.Errorf("error creating security event: %w", err)
	}
	return nil
}
