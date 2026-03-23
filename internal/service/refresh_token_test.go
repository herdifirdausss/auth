package service

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRefreshToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db, sqlMock, _ := sqlmock.New()
	defer db.Close()

	rfRepo := repository.NewMockRefreshTokenRepository(ctrl)
	sessRepo := repository.NewMockSessionRepository(ctrl)
	eventRepo := repository.NewMockSecurityEventRepository(ctrl)
	
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

	rfRepo.EXPECT().FindByTokenHash(gomock.Any(), refreshHash).Return(token, nil)
	sessRepo.EXPECT().FindByID(gomock.Any(), "sess-1").Return(&model.Session{ID: "sess-1", UserID: "user-1"}, nil)
	sqlMock.ExpectBegin()
	rfRepo.EXPECT().MarkUsed(gomock.Any(), gomock.Any(), "rt-1").Return(nil)
	rfRepo.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	sessRepo.EXPECT().UpdateActivity(gomock.Any(), "sess-1").Return(nil)
	sqlMock.ExpectCommit()

	res, err := s.RefreshToken(context.Background(), rawRefresh, "1.1.1.1", "ua")
	
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
}

func TestRefreshToken_ReuseDetection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	db, sqlMock, _ := sqlmock.New()
	defer db.Close()

	rfRepo := repository.NewMockRefreshTokenRepository(ctrl)
	sessRepo := repository.NewMockSessionRepository(ctrl)
	eventRepo := repository.NewMockSecurityEventRepository(ctrl)
	
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

	rfRepo.EXPECT().FindByTokenHash(gomock.Any(), refreshHash).Return(token, nil)
	eventRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
	sqlMock.ExpectBegin()
	rfRepo.EXPECT().RevokeByFamily(gomock.Any(), gomock.Any(), "fam-1").Return(nil)
	sessRepo.EXPECT().RevokeByID(gomock.Any(), "sess-1", "refresh_token_reuse", "system").Return(nil)
	sqlMock.ExpectCommit()

	_, err := s.RefreshToken(context.Background(), rawRefresh, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "suspicious activity")
}
