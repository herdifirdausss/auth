package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type RoleRepository interface {
	Create(ctx context.Context, role *model.Role) error
	FindByID(ctx context.Context, id string) (*model.Role, error)
	FindByName(ctx context.Context, tenantID *string, name string) (*model.Role, error)
	GetDefaults(ctx context.Context) ([]model.Role, error)
	FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error)
	FindRolesByMembership(ctx context.Context, membershipID string) ([]model.Role, error)
	FindRolesByUserAndTenant(ctx context.Context, userID, tenantID string) ([]model.Role, error)
	ListByTenant(ctx context.Context, tenantID string) ([]model.Role, error)
	Update(ctx context.Context, role *model.Role) error
	Delete(ctx context.Context, id string) error
}

type PostgresRoleRepository struct {
	db Pool
}

func NewPostgresRoleRepository(db Pool) *PostgresRoleRepository {
	return &PostgresRoleRepository{db: db}
}

func (r *PostgresRoleRepository) Create(ctx context.Context, role *model.Role) error {
	query := `INSERT INTO roles (tenant_id, name, description, permissions, is_system) 
	          VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, updated_at`

	permsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return err
	}

	return r.db.QueryRow(ctx, query, role.TenantID, role.Name, role.Description, permsJSON, role.IsSystem).
		Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
}

func (r *PostgresRoleRepository) FindByID(ctx context.Context, id string) (*model.Role, error) {
	query := `SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at 
	          FROM roles WHERE id = $1`

	var role model.Role
	var permsJSON []byte
	err := r.db.QueryRow(ctx, query, id).Scan(
		&role.ID, &role.TenantID, &role.Name, &role.Description, &permsJSON,
		&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if len(permsJSON) > 0 {
		if err := json.Unmarshal(permsJSON, &role.Permissions); err != nil {
			return nil, err
		}
	} else {
		role.Permissions = []string{}
	}

	return &role, nil
}

func (r *PostgresRoleRepository) FindByName(ctx context.Context, tenantID *string, name string) (*model.Role, error) {
	var query string
	var row pgx.Row
	if tenantID == nil {
		query = `SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at 
		          FROM roles WHERE tenant_id IS NULL AND LOWER(name) = LOWER($1)`
		row = r.db.QueryRow(ctx, query, name)
	} else {
		query = `SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at 
		          FROM roles WHERE tenant_id = $1 AND LOWER(name) = LOWER($2)`
		row = r.db.QueryRow(ctx, query, *tenantID, name)
	}

	var role model.Role
	var permsJSON []byte
	err := row.Scan(
		&role.ID, &role.TenantID, &role.Name, &role.Description, &permsJSON,
		&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if len(permsJSON) > 0 {
		if err := json.Unmarshal(permsJSON, &role.Permissions); err != nil {
			return nil, err
		}
	} else {
		role.Permissions = []string{}
	}

	return &role, nil
}

func (r *PostgresRoleRepository) GetDefaults(ctx context.Context) ([]model.Role, error) {
	query := `SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at 
	          FROM roles WHERE is_system = true AND tenant_id IS NULL`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []model.Role
	for rows.Next() {
		var role model.Role
		var permsJSON []byte
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.Description, &permsJSON,
			&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if len(permsJSON) > 0 {
			if err := json.Unmarshal(permsJSON, &role.Permissions); err != nil {
				return nil, err
			}
		} else {
			role.Permissions = []string{}
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (r *PostgresRoleRepository) FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error) {
	query := `
		SELECT DISTINCT p.permission
		FROM tenant_memberships m
		JOIN membership_roles mr ON m.id = mr.membership_id
		JOIN roles r ON mr.role_id = r.id
		CROSS JOIN jsonb_array_elements_text(r.permissions) AS p(permission)
		WHERE m.user_id = $1 AND m.tenant_id = $2 AND m.status = 'active'
	`
	rows, err := r.db.Query(ctx, query, userID, tenantID)
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

func (r *PostgresRoleRepository) FindRolesByMembership(ctx context.Context, membershipID string) ([]model.Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.name, r.description, r.permissions, r.is_system, r.created_at, r.updated_at
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
			&permsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
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
func (r *PostgresRoleRepository) FindRolesByUserAndTenant(ctx context.Context, userID, tenantID string) ([]model.Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.name, r.description, r.permissions, r.is_system, r.created_at, r.updated_at
		FROM roles r
		JOIN membership_roles mr ON r.id = mr.role_id
		JOIN tenant_memberships tm ON mr.membership_id = tm.id
		WHERE tm.user_id = $1 AND tm.tenant_id = $2 AND tm.status = 'active'
	`
	rows, err := r.db.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("error finding roles by user and tenant: %w", err)
	}
	defer rows.Close()

	var roles []model.Role
	for rows.Next() {
		var role model.Role
		var permsJSON []byte
		if err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.Description,
			&permsJSON, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
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

func (r *PostgresRoleRepository) ListByTenant(ctx context.Context, tenantID string) ([]model.Role, error) {
	query := `SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at 
	          FROM roles WHERE tenant_id = $1`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []model.Role
	for rows.Next() {
		var role model.Role
		var permsJSON []byte
		err := rows.Scan(
			&role.ID, &role.TenantID, &role.Name, &role.Description, &permsJSON,
			&role.IsSystem, &role.CreatedAt, &role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if len(permsJSON) > 0 {
			if err := json.Unmarshal(permsJSON, &role.Permissions); err != nil {
				return nil, err
			}
		} else {
			role.Permissions = []string{}
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (r *PostgresRoleRepository) Update(ctx context.Context, role *model.Role) error {
	query := `UPDATE roles SET name = $1, description = $2, permissions = $3, updated_at = now() 
	          WHERE id = $4`
	permsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, query, role.Name, role.Description, permsJSON, role.ID)
	return err
}

func (r *PostgresRoleRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM roles WHERE id = $1 AND is_system = false`
	_, err := r.db.Exec(ctx, query, id)
	return err
}
