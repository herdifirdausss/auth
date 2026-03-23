package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=repository
type SessionRepository interface {
	Create(ctx context.Context, tx *sql.Tx, session *model.Session) error
	FindByID(ctx context.Context, id string) (*model.Session, error)
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
	RevokeByID(ctx context.Context, sessionID, reason, revokedBy string) error
	RevokeAllByUser(ctx context.Context, tx *sql.Tx, userID, reason string) error
	UpdateActivity(ctx context.Context, sessionID string) error
	CleanupExpired(ctx context.Context) (int64, error)
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

func (r *PostgresSessionRepository) FindByID(ctx context.Context, id string) (*model.Session, error) {
	query := `SELECT id, user_id, tenant_id, token_hash, mfa_verified, expires_at, idle_timeout_at, revoked_at 
	          FROM sessions WHERE id = $1`
	
	var sess model.Session
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&sess.ID, &sess.UserID, &sess.TenantID, &sess.TokenHash, 
		&sess.MFAVerified, &sess.ExpiresAt, &sess.IdleTimeoutAt, &sess.RevokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding session by id: %w", err)
	}
	return &sess, nil
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

func (r *PostgresSessionRepository) RevokeByID(ctx context.Context, sessionID, reason, revokedBy string) error {
	query := `UPDATE sessions SET revoked_at = now(), revoked_reason = $1, revoked_by = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, query, reason, revokedBy, sessionID)
	return err
}
func (r *PostgresSessionRepository) CleanupExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE (expires_at < now() OR idle_timeout_at < now()) AND revoked_at IS NULL`
	// Actually, should we delete revoked ones too? Yes, after some time.
	// But the requirement says "expired".
	res, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *PostgresSessionRepository) RevokeAllByUser(ctx context.Context, tx *sql.Tx, userID, reason string) error {
	query := `UPDATE sessions SET revoked_at = now(), revoked_reason = $2 
	          WHERE user_id = $1 AND revoked_at IS NULL`
	
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID, reason)
	} else {
		_, err = r.db.ExecContext(ctx, query, userID, reason)
	}
	return err
}

func (r *PostgresSessionRepository) UpdateActivity(ctx context.Context, sessionID string) error {
	query := `UPDATE sessions SET last_activity_at = now(), idle_timeout_at = now() + interval '30 minutes', updated_at = now() 
	          WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, sessionID)
	return err
}

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=repository
type RefreshTokenRepository interface {
	Create(ctx context.Context, tx *sql.Tx, token *model.RefreshToken) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error)
	MarkUsed(ctx context.Context, tx *sql.Tx, tokenID string) error
	RevokeBySessionID(ctx context.Context, tx *sql.Tx, sessionID string) error
	RevokeByFamily(ctx context.Context, tx *sql.Tx, familyID string) error
	RevokeAllByUser(ctx context.Context, tx *sql.Tx, userID string) error
	CleanupExpired(ctx context.Context) (int64, error)
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

func (r *PostgresRefreshTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error) {
	query := `SELECT id, session_id, user_id, token_hash, family_id, generation, parent_token_id, 
	          revoked_at, used_at, expires_at FROM refresh_tokens WHERE token_hash = $1`
	
	var t model.RefreshToken
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&t.ID, &t.SessionID, &t.UserID, &t.TokenHash, &t.FamilyID, &t.Generation, &t.ParentTokenID,
		&t.RevokedAt, &t.UsedAt, &t.ExpiresAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding refresh token: %w", err)
	}
	return &t, nil
}

func (r *PostgresRefreshTokenRepository) MarkUsed(ctx context.Context, tx *sql.Tx, tokenID string) error {
	query := `UPDATE refresh_tokens SET used_at = now() WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, tokenID)
	} else {
		_, err = r.db.ExecContext(ctx, query, tokenID)
	}
	return err
}

func (r *PostgresRefreshTokenRepository) RevokeBySessionID(ctx context.Context, tx *sql.Tx, sessionID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = now() WHERE session_id = $1 AND revoked_at IS NULL`
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, sessionID)
	} else {
		_, err = r.db.ExecContext(ctx, query, sessionID)
	}
	return err
}

func (r *PostgresRefreshTokenRepository) RevokeByFamily(ctx context.Context, tx *sql.Tx, familyID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, familyID)
	} else {
		_, err = r.db.ExecContext(ctx, query, familyID)
	}
	return err
}

func (r *PostgresRefreshTokenRepository) RevokeAllByUser(ctx context.Context, tx *sql.Tx, userID string) error {
	query := `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`
	var err error
	if tx != nil {
		_, err = tx.ExecContext(ctx, query, userID)
	} else {
		_, err = r.db.ExecContext(ctx, query, userID)
	}
	return err
}

func (r *PostgresRefreshTokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked_at < now() - interval '30 days'`
	res, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
