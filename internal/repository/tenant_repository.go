package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

type TenantRepository interface {
	FindBySlug(ctx context.Context, slug string) (*model.Tenant, error)
}

type PostgresTenantRepository struct {
	db *sql.DB
}

func NewPostgresTenantRepository(db *sql.DB) *PostgresTenantRepository {
	return &PostgresTenantRepository{db: db}
}

func (r *PostgresTenantRepository) FindBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	query := `SELECT id, name, slug, created_at FROM tenants WHERE LOWER(slug) = LOWER($1)`
	var tenant model.Tenant
	err := r.db.QueryRowContext(ctx, query, slug).Scan(&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding tenant by slug: %w", err)
	}
	return &tenant, nil
}

type TenantMembershipRepository interface {
	Create(ctx context.Context, tx *sql.Tx, membership *model.TenantMembership) error
	FindActiveByUserID(ctx context.Context, userID string) (*model.TenantMembership, error)
}

type PostgresTenantMembershipRepository struct {
	db *sql.DB
}

func NewPostgresTenantMembershipRepository(db *sql.DB) *PostgresTenantMembershipRepository {
	return &PostgresTenantMembershipRepository{db: db}
}

func (r *PostgresTenantMembershipRepository) Create(ctx context.Context, tx *sql.Tx, membership *model.TenantMembership) error {
	query := `INSERT INTO tenant_memberships (user_id, tenant_id, status) VALUES ($1, $2, $3) RETURNING id, created_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRowContext(ctx, query, membership.UserID, membership.TenantID, membership.Status).
			Scan(&membership.ID, &membership.CreatedAt)
	} else {
		err = r.db.QueryRowContext(ctx, query, membership.UserID, membership.TenantID, membership.Status).
			Scan(&membership.ID, &membership.CreatedAt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating membership: %w", err)
	}
	return nil
}

func (r *PostgresTenantMembershipRepository) FindActiveByUserID(ctx context.Context, userID string) (*model.TenantMembership, error) {
	query := `SELECT id, user_id, tenant_id, status, created_at FROM tenant_memberships WHERE user_id = $1 AND status = 'active' LIMIT 1`
	var m model.TenantMembership
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&m.ID, &m.UserID, &m.TenantID, &m.Status, &m.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding active membership: %w", err)
	}
	return &m, nil
}
