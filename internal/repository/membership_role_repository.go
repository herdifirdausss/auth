package repository

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type MembershipRoleRepository interface {
	AddRole(ctx context.Context, tx pgx.Tx, membershipID, roleID string) error
	RemoveRole(ctx context.Context, tx pgx.Tx, membershipID, roleID string) error
	RemoveAllRoles(ctx context.Context, tx pgx.Tx, membershipID string) error
}

type PostgresMembershipRoleRepository struct {
	db Pool
}

func NewPostgresMembershipRoleRepository(db Pool) *PostgresMembershipRoleRepository {
	return &PostgresMembershipRoleRepository{db: db}
}

func (r *PostgresMembershipRoleRepository) AddRole(ctx context.Context, tx pgx.Tx, membershipID, roleID string) error {
	query := `INSERT INTO membership_roles (membership_id, role_id) VALUES ($1, $2)`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, membershipID, roleID)
	} else {
		_, err = r.db.Exec(ctx, query, membershipID, roleID)
	}
	if err != nil {
		return fmt.Errorf("error adding role to membership: %w", err)
	}
	return nil
}

func (r *PostgresMembershipRoleRepository) RemoveRole(ctx context.Context, tx pgx.Tx, membershipID, roleID string) error {
	query := `DELETE FROM membership_roles WHERE membership_id = $1 AND role_id = $2`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, membershipID, roleID)
	} else {
		_, err = r.db.Exec(ctx, query, membershipID, roleID)
	}
	if err != nil {
		return fmt.Errorf("error removing role from membership: %w", err)
	}
	return nil
}

func (r *PostgresMembershipRoleRepository) RemoveAllRoles(ctx context.Context, tx pgx.Tx, membershipID string) error {
	query := `DELETE FROM membership_roles WHERE membership_id = $1`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, query, membershipID)
	} else {
		_, err = r.db.Exec(ctx, query, membershipID)
	}
	if err != nil {
		return fmt.Errorf("error removing all roles from membership: %w", err)
	}
	return nil
}
