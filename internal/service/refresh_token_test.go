package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestRefreshToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockTransactor(ctrl)
	mockTx := mocks.NewMockTx(ctrl)

	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	eventRepo := mocks.NewMockSecurityEventRepository(ctrl)
	
	s := &AuthServiceImpl{
		db: mockDB,
		refreshTokenRepo: rfRepo,
		sessionRepo: sessRepo,
		eventRepo: eventRepo,
		jwtConfig: security.JWTConfig{
			SecretKey: []byte("test"),
			AccessExpiry: 15 * time.Minute,
		},
		logger: slog.Default(),
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
	
	mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
	rfRepo.EXPECT().MarkUsed(gomock.Any(), mockTx, "rt-1").Return(nil)
	rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil)
	sessRepo.EXPECT().UpdateActivity(gomock.Any(), "sess-1").Return(nil)
	mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
	mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	res, err := s.RefreshToken(context.Background(), rawRefresh, "1.1.1.1", "ua")
	
	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
}

func TestRefreshToken_ReuseDetection(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockTransactor(ctrl)
	mockTx := mocks.NewMockTx(ctrl)

	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	eventRepo := mocks.NewMockSecurityEventRepository(ctrl)
	
	s := &AuthServiceImpl{
		db: mockDB,
		refreshTokenRepo: rfRepo,
		sessionRepo: sessRepo,
		eventRepo: eventRepo,
		logger: slog.Default(),
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
	
	mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
	rfRepo.EXPECT().RevokeByFamily(gomock.Any(), mockTx, "fam-1").Return(nil)
	sessRepo.EXPECT().RevokeByID(gomock.Any(), "sess-1", "refresh_token_reuse", "system").Return(nil)
	mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
	mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	_, err := s.RefreshToken(context.Background(), rawRefresh, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "suspicious activity")
}
func TestRefreshToken_SessionRevoked_TOCTOU(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockDB := mocks.NewMockTransactor(ctrl)
	mockTx := mocks.NewMockTx(ctrl)

	rfRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	sessRepo := mocks.NewMockSessionRepository(ctrl)
	
	s := &AuthServiceImpl{
		db: mockDB,
		refreshTokenRepo: rfRepo,
		sessionRepo: sessRepo,
		logger: slog.Default(),
	}

	rawRefresh := "valid-token"
	refreshHash := security.HashToken(rawRefresh)
	
	token := &model.RefreshToken{
		ID: "rt-1",
		SessionID: "sess-1",
		UserID: "user-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	rfRepo.EXPECT().FindByTokenHash(gomock.Any(), refreshHash).Return(token, nil)
	
	mockDB.EXPECT().Begin(gomock.Any()).Return(mockTx, nil)
	rfRepo.EXPECT().MarkUsed(gomock.Any(), mockTx, "rt-1").Return(nil)
	rfRepo.EXPECT().Create(gomock.Any(), mockTx, gomock.Any()).Return(nil)
	sessRepo.EXPECT().UpdateActivity(gomock.Any(), "sess-1").Return(nil)
	mockTx.EXPECT().Commit(gomock.Any()).Return(nil)
	mockTx.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	// Simulation: Session is revoked just before generating JWT
	sessRepo.EXPECT().FindByID(gomock.Any(), "sess-1").Return(&model.Session{ID: "sess-1", RevokedAt: &[]time.Time{time.Now()}[0]}, nil)

	_, err := s.RefreshToken(context.Background(), rawRefresh, "1.1.1.1", "ua")
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session revoked")
}
