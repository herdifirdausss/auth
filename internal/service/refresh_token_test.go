package service

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRefreshToken_Success(t *testing.T) {
	db, sqlMock, _ := sqlmock.New()
	defer db.Close()

	rfRepo := new(mockRefreshTokenRepo)
	sessRepo := new(mockSessionRepo)
	eventRepo := new(mockSecurityEventRepo) // already defined in other tests or need definition
	
	s := &AuthServiceImpl{
		db: db,
		refreshTokenRepo: rfRepo,
		sessionRepo: sessRepo,
		eventRepo: eventRepo,
		jwtConfig: security.JWTConfig{
			SecretKey: []byte("test"),
			AccessExpiry: 15 * time.Minute,
		},
	}

	rawRefresh := "old-refresh-token"
	refreshHash := security.HashToken(rawRefresh)
	
	token := &model.RefreshToken{
		ID: "rt-1",
		SessionID: "sess-1",
		UserID: "user-1",
		FamilyID: "fam-1",
		Generation: 1,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	rfRepo.On("FindByTokenHash", mock.Anything, refreshHash).Return(token, nil)
	sqlMock.ExpectBegin()
	rfRepo.On("MarkUsed", mock.Anything, mock.Anything, "rt-1").Return(nil)
	rfRepo.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	sessRepo.On("UpdateActivity", mock.Anything, "sess-1").Return(nil)
	sqlMock.ExpectCommit()

	res, err := s.RefreshToken(context.Background(), rawRefresh, "1.1.1.1", "ua")
	
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	rfRepo.AssertExpectations(t)
	sessRepo.AssertExpectations(t)
}

func TestRefreshToken_ReuseDetection(t *testing.T) {
	db, sqlMock, _ := sqlmock.New()
	defer db.Close()

	rfRepo := new(mockRefreshTokenRepo)
	sessRepo := new(mockSessionRepo)
	eventRepo := new(mockSecurityEventRepo)
	
	s := &AuthServiceImpl{
		db: db,
		refreshTokenRepo: rfRepo,
		sessionRepo: sessRepo,
		eventRepo: eventRepo,
	}

	rawRefresh := "reused-token"
	refreshHash := security.HashToken(rawRefresh)
	
	now := time.Now()
	token := &model.RefreshToken{
		ID: "rt-1",
		SessionID: "sess-1",
		UserID: "user-1",
		FamilyID: "fam-1",
		UsedAt: &now,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	rfRepo.On("FindByTokenHash", mock.Anything, refreshHash).Return(token, nil)
	eventRepo.On("Create", mock.Anything, mock.Anything).Return(nil)
	sqlMock.ExpectBegin()
	rfRepo.On("RevokeByFamily", mock.Anything, mock.Anything, "fam-1").Return(nil)
	sessRepo.On("Revoke", mock.Anything, "sess-1", "refresh_token_reuse").Return(nil)
	sqlMock.ExpectCommit()

	_, err := s.RefreshToken(context.Background(), rawRefresh, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "suspicious activity")
	rfRepo.AssertExpectations(t)
	sessRepo.AssertExpectations(t)
	eventRepo.AssertExpectations(t)
}
