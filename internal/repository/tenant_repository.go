package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type TenantRepository interface {
	FindByID(ctx context.Context, id string) (*model.Tenant, error)
	FindBySlug(ctx context.Context, slug string) (*model.Tenant, error)
	Create(ctx context.Context, tx pgx.Tx, tenant *model.Tenant) error
	UpdateStatus(ctx context.Context, id string, isActive bool) error
	UpdateSettings(ctx context.Context, id string, settings map[string]interface{}) error
	SoftDelete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*model.Tenant, error)
}

type PostgresTenantRepository struct {
	db Pool
}

func NewPostgresTenantRepository(db Pool) *PostgresTenantRepository {
	return &PostgresTenantRepository{db: db}
}

func (r *PostgresTenantRepository) FindByID(ctx context.Context, id string) (*model.Tenant, error) {
	query := `SELECT id, name, slug, settings, is_active, created_at, updated_at FROM tenants WHERE id = $1 AND deleted_at IS NULL`
	var tenant model.Tenant
	err := r.db.QueryRow(ctx, query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Settings, &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding tenant by id: %w", err)
	}
	return &tenant, nil
}

func (r *PostgresTenantRepository) FindBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	query := `SELECT id, name, slug, settings, is_active, created_at, updated_at FROM tenants 
	          WHERE LOWER(slug) = LOWER($1) AND deleted_at IS NULL`
	var tenant model.Tenant
	err := r.db.QueryRow(ctx, query, slug).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Settings, &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding tenant by slug: %w", err)
	}
	return &tenant, nil
}

func (r *PostgresTenantRepository) Create(ctx context.Context, tx pgx.Tx, tenant *model.Tenant) error {
	if tenant.Settings == nil {
		tenant.Settings = make(map[string]interface{})
	}
	query := `INSERT INTO tenants (name, slug, settings, is_active) VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, query, tenant.Name, tenant.Slug, tenant.Settings, tenant.IsActive).
			Scan(&tenant.ID, &tenant.CreatedAt, &tenant.UpdatedAt)
	} else {
		err = r.db.QueryRow(ctx, query, tenant.Name, tenant.Slug, tenant.Settings, tenant.IsActive).
			Scan(&tenant.ID, &tenant.CreatedAt, &tenant.UpdatedAt)
	}
	if err != nil {
		return fmt.Errorf("error creating tenant: %w", err)
	}
	return nil
}

func (r *PostgresTenantRepository) UpdateStatus(ctx context.Context, id string, isActive bool) error {
	query := `UPDATE tenants SET is_active = $1, updated_at = now() WHERE id = $2`
	_, err := r.db.Exec(ctx, query, isActive, id)
	return err
}

func (r *PostgresTenantRepository) UpdateSettings(ctx context.Context, id string, settings map[string]interface{}) error {
	query := `UPDATE tenants SET settings = $1, updated_at = now() WHERE id = $2`
	_, err := r.db.Exec(ctx, query, settings, id)
	return err
}

func (r *PostgresTenantRepository) SoftDelete(ctx context.Context, id string) error {
	query := `UPDATE tenants SET deleted_at = now(), updated_at = now() WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	return err
}

func (r *PostgresTenantRepository) List(ctx context.Context) ([]*model.Tenant, error) {
	query := `SELECT id, name, slug, settings, is_active, created_at, updated_at FROM tenants WHERE deleted_at IS NULL ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error querying tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*model.Tenant
	for rows.Next() {
		var t model.Tenant
		err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Settings, &t.IsActive, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("error scanning tenant: %w", err)
		}
		tenants = append(tenants, &t)
	}
	return tenants, nil
}

// directive for the whole file is already at the top
type TenantMembershipRepository interface {
	Create(ctx context.Context, tx pgx.Tx, membership *model.TenantMembership) error
	FindActiveByUserID(ctx context.Context, userID string) (*model.TenantMembership, error)
	FindByUserAndTenant(ctx context.Context, userID, tenantID string) (*model.TenantMembership, error)
	FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error)
	FindRolesByMembership(ctx context.Context, membershipID string) ([]model.Role, error)
	ActivateByUserID(ctx context.Context, tx pgx.Tx, userID string) error
	UpdateStatus(ctx context.Context, tx pgx.Tx, id string, status string, acceptedAt *time.Time) error
	ListByTenant(ctx context.Context, tenantID string) ([]model.TenantMembership, error)
	Delete(ctx context.Context, tx pgx.Tx, id string) error
	FindByID(ctx context.Context, id string) (*model.TenantMembership, error)
}

type PostgresTenantMembershipRepository struct {
	db Pool
}

func NewPostgresTenantMembershipRepository(db Pool) *PostgresTenantMembershipRepository {
	return &PostgresTenantMembershipRepository{db: db}
}

func (r *PostgresTenantMembershipRepository) Create(ctx context.Context, tx pgx.Tx, membership *model.TenantMembership) error {
	query := `INSERT INTO tenant_memberships (user_id, tenant_id, status, invited_by) 
	          VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, query, membership.UserID, membership.TenantID, membership.Status, membership.InvitedBy).
			Scan(&membership.ID, &membership.CreatedAt, &membership.UpdatedAt)
	} else {
		err = r.db.QueryRow(ctx, query, membership.UserID, membership.TenantID, membership.Status, membership.InvitedBy).
			Scan(&membership.ID, &membership.CreatedAt, &membership.UpdatedAt)
	}
	
	if err != nil {
		return fmt.Errorf("error creating membership: %w", err)
	}
	return nil
}

func (r *PostgresTenantMembershipRepository) FindByUserAndTenant(ctx context.Context, userID, tenantID string) (*model.TenantMembership, error) {
	query := `SELECT id, user_id, tenant_id, status, invited_by, invited_at, accepted_at, created_at, updated_at 
	          FROM tenant_memberships WHERE user_id = $1 AND tenant_id = $2`
	var m model.TenantMembership
	err := r.db.QueryRow(ctx, query, userID, tenantID).Scan(
		&m.ID, &m.UserID, &m.TenantID, &m.Status, &m.InvitedBy, &m.InvitedAt, &m.AcceptedAt, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding membership: %w", err)
	}
	return &m, nil
}

func (r *PostgresTenantMembershipRepository) UpdateStatus(ctx context.Context, tx pgx.Tx, id string, status string, acceptedAt *time.Time) error {
	query := `UPDATE tenant_memberships SET status = $1, accepted_at = $2, updated_at = now() WHERE id = $3`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, status, acceptedAt, id)
	} else {
		_, err = r.db.Exec(ctx, query, status, acceptedAt, id)
	}
	return err
}

func (r *PostgresTenantMembershipRepository) FindActiveByUserID(ctx context.Context, userID string) (*model.TenantMembership, error) {
	query := `SELECT id, user_id, tenant_id, status, created_at FROM tenant_memberships WHERE user_id = $1 AND status = 'active'`
	var m model.TenantMembership
	err := r.db.QueryRow(ctx, query, userID).Scan(&m.ID, &m.UserID, &m.TenantID, &m.Status, &m.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

func (r *PostgresTenantMembershipRepository) FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error) {
	query := `
		SELECT DISTINCT p
		FROM tenant_memberships tm
		JOIN membership_roles mr ON tm.id = mr.membership_id
		JOIN roles r ON mr.role_id = r.id
		CROSS JOIN LATERAL jsonb_array_elements_text(r.permissions) AS p
		WHERE tm.user_id = $1 AND tm.tenant_id = $2 AND tm.status = 'active'
	`
	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, err
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
	rows, err := r.db.Query(ctx, query, membershipID)
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
func (r *PostgresTenantMembershipRepository) ActivateByUserID(ctx context.Context, tx pgx.Tx, userID string) error {
	query := `UPDATE tenant_memberships SET status = 'active', updated_at = now() WHERE user_id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, userID)
	} else {
		_, err = r.db.Exec(ctx, query, userID)
	}
	if err != nil {
		return fmt.Errorf("error activating membership: %w", err)
	}
	return nil
}
func (r *PostgresTenantMembershipRepository) ListByTenant(ctx context.Context, tenantID string) ([]model.TenantMembership, error) {
	query := `SELECT id, user_id, tenant_id, status, invited_by, invited_at, accepted_at, created_at, updated_at 
	          FROM tenant_memberships WHERE tenant_id = $1`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var memberships []model.TenantMembership
	for rows.Next() {
		var m model.TenantMembership
		err := rows.Scan(&m.ID, &m.UserID, &m.TenantID, &m.Status, &m.InvitedBy, &m.InvitedAt, &m.AcceptedAt, &m.CreatedAt, &m.UpdatedAt)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, m)
	}
	return memberships, nil
}

func (r *PostgresTenantMembershipRepository) Delete(ctx context.Context, tx pgx.Tx, id string) error {
	query := `DELETE FROM tenant_memberships WHERE id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, id)
	} else {
		_, err = r.db.Exec(ctx, query, id)
	}
	return err
}

func (r *PostgresTenantMembershipRepository) FindByID(ctx context.Context, id string) (*model.TenantMembership, error) {
	query := `SELECT id, user_id, tenant_id, status, invited_by, invited_at, accepted_at, created_at, updated_at 
	          FROM tenant_memberships WHERE id = $1`
	var m model.TenantMembership
	err := r.db.QueryRow(ctx, query, id).Scan(
		&m.ID, &m.UserID, &m.TenantID, &m.Status, &m.InvitedBy, &m.InvitedAt, &m.AcceptedAt, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}
