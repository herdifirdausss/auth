package repository

import (
	"context"

	"github.com/herdifirdausss/auth/internal/model"
)

type AuditLogRepository interface {
	Create(ctx context.Context, log *model.AuditLog) error
}
