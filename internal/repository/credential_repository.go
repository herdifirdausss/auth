package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

type CredentialRepository interface {
	Create(ctx context.Context, tx *sql.Tx, cred *model.UserCredential) error
}

type PostgresCredentialRepository struct {
	db *sql.DB
}

func NewPostgresCredentialRepository(db *sql.DB) *PostgresCredentialRepository {
	return &PostgresCredentialRepository{db: db}
}

func (r *PostgresCredentialRepository) Create(ctx context.Context, tx *sql.Tx, cred *model.UserCredential) error {
	query := `INSERT INTO user_credentials (user_id, password_hash, password_salt, password_algo) 
	          VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, query, cred.UserID, cred.PasswordHash, cred.PasswordSalt, cred.PasswordAlgo).
			Scan(&cred.ID, &cred.CreatedAt, &cred.UpdatedAt)
	} else {
		err = r.db.QueryRowContext(ctx, query, cred.UserID, cred.PasswordHash, cred.PasswordSalt, cred.PasswordAlgo).
			Scan(&cred.ID, &cred.CreatedAt, &cred.UpdatedAt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating credential: %w", err)
	}
	return nil
}

type SecurityTokenRepository interface {
	Create(ctx context.Context, token *model.SecurityToken) error
	FindValidToken(ctx context.Context, tokenHash string, tokenType string) (*model.SecurityToken, error)
	MarkUsed(ctx context.Context, tx *sql.Tx, tokenID string) error
}

type PostgresSecurityTokenRepository struct {
	db *sql.DB
}

func NewPostgresSecurityTokenRepository(db *sql.DB) *PostgresSecurityTokenRepository {
	return &PostgresSecurityTokenRepository{db: db}
}

func (r *PostgresSecurityTokenRepository) Create(ctx context.Context, token *model.SecurityToken) error {
	query := `INSERT INTO security_tokens (user_id, token_type, token_hash, expires_at, ip_address, user_agent) 
	          VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`
	
	err := r.db.QueryRowContext(ctx, query, token.UserID, token.TokenType, token.TokenHash, token.ExpiresAt, token.IPAddress, token.UserAgent).
		Scan(&token.ID, &token.CreatedAt)
	
	if err != nil {
		return fmt.Errorf("error creating security token: %w", err)
	}
	return nil
}

func (r *PostgresSecurityTokenRepository) FindValidToken(ctx context.Context, tokenHash string, tokenType string) (*model.SecurityToken, error) {
	query := `SELECT id, user_id, token_type, token_hash, expires_at, used_at, ip_address, user_agent, created_at 
	          FROM security_tokens 
	          WHERE token_hash = $1 AND token_type = $2 AND used_at IS NULL AND expires_at > now()`
	
	var token model.SecurityToken
	err := r.db.QueryRowContext(ctx, query, tokenHash, tokenType).Scan(
		&token.ID, &token.UserID, &token.TokenType, &token.TokenHash, &token.ExpiresAt, &token.UsedAt, 
		&token.IPAddress, &token.UserAgent, &token.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding valid token: %w", err)
	}
	return &token, nil
}

func (r *PostgresSecurityTokenRepository) MarkUsed(ctx context.Context, tx *sql.Tx, tokenID string) error {
	query := `UPDATE security_tokens SET used_at = now() WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, tokenID)
	} else {
		_, err = r.db.ExecContext(ctx, query, tokenID)
	}
	if err != nil {
		return fmt.Errorf("error marking token as used: %w", err)
	}
	return nil
}

type SecurityEventRepository interface {
	Create(ctx context.Context, event *model.SecurityEvent) error
}

type PostgresSecurityEventRepository struct {
	db *sql.DB
}

func NewPostgresSecurityEventRepository(db *sql.DB) *PostgresSecurityEventRepository {
	return &PostgresSecurityEventRepository{db: db}
}

func (r *PostgresSecurityEventRepository) Create(ctx context.Context, event *model.SecurityEvent) error {
	query := `INSERT INTO security_events (user_id, tenant_id, event_type, severity, details, ip_address, user_agent) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at`
	
	err := r.db.QueryRowContext(ctx, query, event.UserID, event.TenantID, event.EventType, event.Severity, event.Details, event.IPAddress, event.UserAgent).
		Scan(&event.ID, &event.CreatedAt)
	
	if err != nil {
		return fmt.Errorf("error creating security event: %w", err)
	}
	return nil
}
