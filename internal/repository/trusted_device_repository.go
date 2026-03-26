package repository

import (
	"context"
	"fmt"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/jackc/pgx/v5"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type TrustedDeviceRepository interface {
	Upsert(ctx context.Context, tx pgx.Tx, device *model.TrustedDevice) error
	FindByUserAndFingerprint(ctx context.Context, userID, fingerprint string) (*model.TrustedDevice, error)
	DeleteExpired(ctx context.Context) error
}

type PostgresTrustedDeviceRepository struct {
	db Pool
}

func NewPostgresTrustedDeviceRepository(db Pool) *PostgresTrustedDeviceRepository {
	return &PostgresTrustedDeviceRepository{db: db}
}

func (r *PostgresTrustedDeviceRepository) Upsert(ctx context.Context, tx pgx.Tx, device *model.TrustedDevice) error {
	query := `
		INSERT INTO trusted_devices (user_id, device_fingerprint, device_name, device_type, trust_level, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, device_fingerprint) WHERE revoked_at IS NULL
		DO UPDATE SET 
			device_name = EXCLUDED.device_name,
			trust_level = EXCLUDED.trust_level,
			expires_at = EXCLUDED.expires_at,
			last_used_at = now()
		RETURNING id, created_at
	`
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, query, device.UserID, device.DeviceFingerprint, device.DeviceName, device.DeviceType, device.TrustLevel, device.ExpiresAt).
			Scan(&device.ID, &device.CreatedAt)
	} else {
		err = r.db.QueryRow(ctx, query, device.UserID, device.DeviceFingerprint, device.DeviceName, device.DeviceType, device.TrustLevel, device.ExpiresAt).
			Scan(&device.ID, &device.CreatedAt)
	}
	if err != nil {
		return fmt.Errorf("error upserting trusted device: %w", err)
	}
	return nil
}

func (r *PostgresTrustedDeviceRepository) FindByUserAndFingerprint(ctx context.Context, userID, fingerprint string) (*model.TrustedDevice, error) {
	query := `
		SELECT id, user_id, device_fingerprint, device_name, device_type, trust_level, last_used_at, expires_at, created_at
		FROM trusted_devices
		WHERE user_id = $1 AND device_fingerprint = $2 AND revoked_at IS NULL AND expires_at > now()
	`
	var d model.TrustedDevice
	err := r.db.QueryRow(ctx, query, userID, fingerprint).Scan(
		&d.ID, &d.UserID, &d.DeviceFingerprint, &d.DeviceName, &d.DeviceType, &d.TrustLevel, &d.LastUsedAt, &d.ExpiresAt, &d.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error finding trusted device: %w", err)
	}
	return &d, nil
}

func (r *PostgresTrustedDeviceRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM trusted_devices WHERE expires_at < now()`
	_, err := r.db.Exec(ctx, query)
	return err
}
