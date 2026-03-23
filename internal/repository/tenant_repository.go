package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=repository
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

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=repository
type TenantMembershipRepository interface {
	Create(ctx context.Context, tx *sql.Tx, membership *model.TenantMembership) error
	FindActiveByUserID(ctx context.Context, userID string) (*model.TenantMembership, error)
	FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error)
	FindRolesByMembership(ctx context.Context, membershipID string) ([]model.Role, error)
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

func (r *PostgresTenantMembershipRepository) FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error) {
	query := `
		SELECT DISTINCT p.permission
		FROM tenant_memberships m
		JOIN membership_roles mr ON m.id = mr.membership_id
		JOIN roles r ON mr.role_id = r.id
		CROSS JOIN jsonb_array_elements_text(r.permissions) AS p(permission)
		WHERE m.user_id = $1 AND m.tenant_id = $2 AND m.status = 'active'
	`
	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("error getting permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		permissions = append(permissions, p)
	}
	return permissions, nil
}

func (r *PostgresTenantMembershipRepository) FindRolesByMembership(ctx context.Context, membershipID string) ([]model.Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.name, r.description, r.permissions, r.created_at, r.updated_at
		FROM roles r
		JOIN membership_roles mr ON r.id = mr.role_id
		WHERE mr.membership_id = $1
	`
	rows, err := r.db.QueryContext(ctx, query, membershipID)
	if err != nil {
		return nil, fmt.Errorf("error finding roles by membership: %w", err)
	}
	defer rows.Close()

	var roles []model.Role
	for rows.Next() {
		var role model.Role
		var permsJSON []byte
		if err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.Description,
			&permsJSON, &role.CreatedAt, &role.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(permsJSON) > 0 {
			if err := json.Unmarshal(permsJSON, &role.Permissions); err != nil {
				return nil, fmt.Errorf("error unmarshaling permissions: %w", err)
			}
		} else {
			role.Permissions = []string{}
		}
		roles = append(roles, role)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}
