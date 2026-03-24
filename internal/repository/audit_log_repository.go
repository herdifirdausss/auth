package repository

import (
	"context"

	"github.com/herdifirdausss/auth/internal/model"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type AuditLogRepository interface {
	Create(ctx context.Context, log *model.AuditLog) error
}
