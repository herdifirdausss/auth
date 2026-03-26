package repository

import (
	"context"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type AuditLogRepository interface {
	Create(ctx context.Context, log *model.AuditLog) error
}

type postgresAuditLogRepository struct {
	db *pgxpool.Pool
}

func NewAuditLogRepository(db *pgxpool.Pool) AuditLogRepository {
	return &postgresAuditLogRepository{db: db}
}

func (r *postgresAuditLogRepository) Create(ctx context.Context, log *model.AuditLog) error {
	query := `
		INSERT INTO audit_logs (
			tenant_id, user_id, action, resource_type, resource_id, 
			old_values, new_values, ip_address, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`
	return r.db.QueryRow(ctx, query,
		log.TenantID,
		log.UserID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.OldValues,
		log.NewValues,
		log.IPAddress,
		log.UserAgent,
		log.CreatedAt,
	).Scan(&log.ID)
}
