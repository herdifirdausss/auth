package service

import (
	"context"
	"database/sql"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/stretchr/testify/mock"
)

type mockMFARepo struct {
	mock.Mock
}

func (m *mockMFARepo) FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.MFAMethod), args.Error(1)
}

func (m *mockMFARepo) Create(ctx context.Context, method *model.MFAMethod) error {
	args := m.Called(ctx, method)
	return args.Error(0)
}

func (m *mockMFARepo) FindInactiveByUser(ctx context.Context, userID, methodType string) (*model.MFAMethod, error) {
	args := m.Called(ctx, userID, methodType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.MFAMethod), args.Error(1)
}

func (m *mockMFARepo) Activate(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockMFARepo) SetBackupCodes(ctx context.Context, id, encrypted string) error {
	args := m.Called(ctx, id, encrypted)
	return args.Error(0)
}

type mockRateLimiter struct {
	mock.Mock
}

func (m *mockRateLimiter) Check(ctx context.Context, cfg redis.RateLimitConfig) (redis.RateLimitResult, error) {
	args := m.Called(ctx, cfg)
	return args.Get(0).(redis.RateLimitResult), args.Error(1)
}

func (m *mockRateLimiter) Reset(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

type mockSessionRepo struct {
	mock.Mock
}

func (m *mockSessionRepo) Create(ctx context.Context, tx *sql.Tx, session *model.Session) error {
	args := m.Called(ctx, tx, session)
	return args.Error(0)
}

func (m *mockSessionRepo) FindByID(ctx context.Context, id string) (*model.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Session), args.Error(1)
}

func (m *mockSessionRepo) FindByTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Session), args.Error(1)
}

func (m *mockSessionRepo) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockSessionRepo) Revoke(ctx context.Context, id string, reason string) error {
	args := m.Called(ctx, id, reason)
	return args.Error(0)
}

func (m *mockSessionRepo) UpdateActivity(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type mockRefreshTokenRepo struct {
	mock.Mock
}

func (m *mockRefreshTokenRepo) Create(ctx context.Context, tx *sql.Tx, token *model.RefreshToken) error {
	args := m.Called(ctx, tx, token)
	return args.Error(0)
}

func (m *mockRefreshTokenRepo) FindByTokenHash(ctx context.Context, hash string) (*model.RefreshToken, error) {
	args := m.Called(ctx, hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RefreshToken), args.Error(1)
}

func (m *mockRefreshTokenRepo) MarkUsed(ctx context.Context, tx *sql.Tx, tokenID string) error {
	args := m.Called(ctx, tx, tokenID)
	return args.Error(0)
}

func (m *mockRefreshTokenRepo) RevokeFamily(ctx context.Context, familyID string) error {
	args := m.Called(ctx, familyID)
	return args.Error(0)
}

func (m *mockRefreshTokenRepo) RevokeByFamily(ctx context.Context, tx *sql.Tx, familyID string) error {
	args := m.Called(ctx, tx, familyID)
	return args.Error(0)
}

func (m *mockRefreshTokenRepo) Revoke(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type mockSecurityEventRepo struct {
	mock.Mock
}

func (m *mockSecurityEventRepo) Create(ctx context.Context, event *model.SecurityEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}
