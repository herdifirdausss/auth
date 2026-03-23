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

func (m *mockSessionRepo) RevokeAllByUser(ctx context.Context, tx *sql.Tx, userID, reason string) error {
	args := m.Called(ctx, tx, userID, reason)
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
	args := m.Called(event)
	return args.Error(0)
}

type mockPasswordHistoryRepo struct {
	mock.Mock
}

func (m *mockPasswordHistoryRepo) GetRecentPasswords(ctx context.Context, userID string, limit int) ([]string, error) {
	args := m.Called(ctx, userID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockPasswordHistoryRepo) Create(ctx context.Context, tx *sql.Tx, userID, passwordHash string) error {
	args := m.Called(ctx, tx, userID, passwordHash)
	return args.Error(0)
}

func (m *mockPasswordHistoryRepo) Cleanup(ctx context.Context, userID string, limit int) error {
	args := m.Called(ctx, userID, limit)
	return args.Error(0)
}

type mockUserRepo struct {
	mock.Mock
}

func (m *mockUserRepo) Create(ctx context.Context, tx *sql.Tx, user *model.User) error {
	args := m.Called(tx, user)
	return args.Error(0)
}

func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *mockUserRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *mockUserRepo) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	args := m.Called(ctx, username)
	return args.Bool(0), args.Error(1)
}

func (m *mockUserRepo) SetVerified(ctx context.Context, tx *sql.Tx, userID string) error {
	args := m.Called(ctx, tx, userID)
	return args.Error(0)
}

func (m *mockUserRepo) IncrementFailedLogin(ctx context.Context, userID string) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

func (m *mockUserRepo) SuspendUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockUserRepo) ResetFailedLoginAndUpdateLastLogin(ctx context.Context, userID string, ip string) error {
	args := m.Called(ctx, userID, ip)
	return args.Error(0)
}

func (m *mockUserRepo) FindByID(ctx context.Context, id string) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

type mockSecurityTokenRepo struct {
	mock.Mock
}

func (m *mockSecurityTokenRepo) Create(ctx context.Context, token *model.SecurityToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *mockSecurityTokenRepo) FindValidToken(ctx context.Context, hash, tokenType string) (*model.SecurityToken, error) {
	args := m.Called(ctx, hash, tokenType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.SecurityToken), args.Error(1)
}

func (m *mockSecurityTokenRepo) MarkUsed(ctx context.Context, tx *sql.Tx, id string) error {
	args := m.Called(ctx, tx, id)
	return args.Error(0)
}

type mockCredentialRepo struct {
	mock.Mock
}

func (m *mockCredentialRepo) Create(ctx context.Context, tx *sql.Tx, cred *model.UserCredential) error {
	args := m.Called(cred)
	return args.Error(0)
}

func (m *mockCredentialRepo) FindByUserID(ctx context.Context, userID string) (*model.UserCredential, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserCredential), args.Error(1)
}

func (m *mockCredentialRepo) UpdatePassword(ctx context.Context, tx *sql.Tx, userID, hash, salt string) error {
	args := m.Called(ctx, tx, userID, hash, salt)
	return args.Error(0)
}

type mockPasswordHasher struct {
	mock.Mock
}

func (m *mockPasswordHasher) Hash(password string) (string, string, error) {
	args := m.Called(password)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *mockPasswordHasher) Verify(password, hash, salt string) (bool, error) {
	args := m.Called(password, hash, salt)
	return args.Bool(0), args.Error(1)
}
