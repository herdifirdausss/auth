package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

type SessionRepository interface {
	Create(ctx context.Context, tx *sql.Tx, session *model.Session) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
	Revoke(ctx context.Context, sessionID string, reason string) error
}

type PostgresSessionRepository struct {
	db *sql.DB
}

func NewPostgresSessionRepository(db *sql.DB) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

func (r *PostgresSessionRepository) Create(ctx context.Context, tx *sql.Tx, session *model.Session) error {
	query := `INSERT INTO sessions (user_id, tenant_id, membership_id, token_hash, ip_address, user_agent, 
	          device_fingerprint, device_name, expires_at, idle_timeout_at) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, created_at, updated_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, query, session.UserID, session.TenantID, session.MembershipID, 
			session.TokenHash, session.IPAddress, session.UserAgent, session.DeviceFingerprint, 
			session.DeviceName, session.ExpiresAt, session.IdleTimeoutAt).
			Scan(&session.ID, &session.CreatedAt, &session.UpdatedAt)
	} else {
		err = r.db.QueryRowContext(ctx, query, session.UserID, session.TenantID, session.MembershipID, 
			session.TokenHash, session.IPAddress, session.UserAgent, session.DeviceFingerprint, 
			session.DeviceName, session.ExpiresAt, session.IdleTimeoutAt).
			Scan(&session.ID, &session.CreatedAt, &session.UpdatedAt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating session: %w", err)
	}
	return nil
}

func (r *PostgresSessionRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	query := `SELECT id, user_id, tenant_id, membership_id, token_hash, mfa_verified, expires_at, idle_timeout_at 
	          FROM sessions WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`
	
	var sess model.Session
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&sess.ID, &sess.UserID, &sess.TenantID, &sess.MembershipID, &sess.TokenHash, 
		&sess.MFAVerified, &sess.ExpiresAt, &sess.IdleTimeoutAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding session: %w", err)
	}
	return &sess, nil
}

func (r *PostgresSessionRepository) Revoke(ctx context.Context, sessionID string, reason string) error {
	query := `UPDATE sessions SET revoked_at = now(), revoked_reason = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, reason, sessionID)
	return err
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, tx *sql.Tx, token *model.RefreshToken) error
}

type PostgresRefreshTokenRepository struct {
	db *sql.DB
}

func NewPostgresRefreshTokenRepository(db *sql.DB) *PostgresRefreshTokenRepository {
	return &PostgresRefreshTokenRepository{db: db}
}

func (r *PostgresRefreshTokenRepository) Create(ctx context.Context, tx *sql.Tx, token *model.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (session_id, user_id, token_hash, family_id, generation, 
	          parent_token_id, ip_address, device_fingerprint, expires_at) 
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, created_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, query, token.SessionID, token.UserID, token.TokenHash, 
			token.FamilyID, token.Generation, token.ParentTokenID, token.IPAddress, 
			token.DeviceFingerprint, token.ExpiresAt).
			Scan(&token.ID, &token.CreatedAt)
	} else {
		err = r.db.QueryRowContext(ctx, query, token.SessionID, token.UserID, token.TokenHash, 
			token.FamilyID, token.Generation, token.ParentTokenID, token.IPAddress, 
			token.DeviceFingerprint, token.ExpiresAt).
			Scan(&token.ID, &token.CreatedAt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating refresh token: %w", err)
	}
	return nil
}
