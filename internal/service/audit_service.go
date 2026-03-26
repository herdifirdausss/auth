package service

import (
	"context"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type AuditService interface {
	Log(ctx context.Context, action string, userID *string, tenantID *string, resourceType string, resourceID *string, oldValues, newValues interface{}, ip, ua string) error
	LogAction(ctx context.Context, action string, userID *string, resourceType string, resourceID *string) error
}

type auditService struct {
	repo repository.AuditLogRepository
}

func NewAuditService(repo repository.AuditLogRepository) AuditService {
	return &auditService{repo: repo}
}

func (s *auditService) Log(ctx context.Context, action string, userID *string, tenantID *string, resourceType string, resourceID *string, oldValues, newValues interface{}, ip, ua string) error {
	log := &model.AuditLog{
		TenantID:     tenantID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		OldValues:    oldValues,
		NewValues:    newValues,
		IPAddress:    ip,
		UserAgent:    ua,
		CreatedAt:    time.Now(),
	}
	return s.repo.Create(ctx, log)
}

func (s *auditService) LogAction(ctx context.Context, action string, userID *string, resourceType string, resourceID *string) error {
	return s.Log(ctx, action, userID, nil, resourceType, resourceID, nil, nil, "", "")
}
