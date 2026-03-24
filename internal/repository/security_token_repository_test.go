package repository

import (
	"context"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
)

func TestPostgresSecurityTokenRepository_Create(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresSecurityTokenRepository(mock)
	ctx := context.Background()

	token := &model.SecurityToken{
		UserID:    "user-1",
		TokenType: "password_reset",
		TokenHash: "hash",
		ExpiresAt: time.Now().Add(time.Hour),
		IPAddress: "127.0.0.1",
		UserAgent: "ua",
	}

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(`INSERT INTO security_tokens`).
			WithArgs(token.UserID, token.TokenType, token.TokenHash, token.ExpiresAt, token.IPAddress, token.UserAgent).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).
				AddRow("token-1", time.Now()))

		err := repo.Create(ctx, token)
		assert.NoError(t, err)
		assert.Equal(t, "token-1", token.ID)
	})
}

func TestPostgresSecurityTokenRepository_FindValidToken(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresSecurityTokenRepository(mock)
	ctx := context.Background()
	tokenHash := "hash"
	tokenType := "password_reset"

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(`SELECT (.+) FROM security_tokens WHERE token_hash = \$1 AND token_type = \$2`).
			WithArgs(tokenHash, tokenType).
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "token_type", "token_hash", "expires_at", "used_at", "ip_address", "user_agent", "created_at"}).
				AddRow("token-1", "user-1", tokenType, tokenHash, time.Now().Add(time.Hour), nil, "127.0.0.1", "ua", time.Now()))

		token, err := repo.FindValidToken(ctx, tokenHash, tokenType)
		assert.NoError(t, err)
		assert.NotNil(t, token)
	})

	t.Run("NotFound", func(t *testing.T) {
		mock.ExpectQuery(`SELECT (.+) FROM security_tokens WHERE token_hash = \$1 AND token_type = \$2`).
			WithArgs(tokenHash, tokenType).
			WillReturnRows(pgxmock.NewRows([]string{"id"}))

		token, err := repo.FindValidToken(ctx, tokenHash, tokenType)
		assert.NoError(t, err)
		assert.Nil(t, token)
	})
}

func TestPostgresSecurityTokenRepository_MarkUsed(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresSecurityTokenRepository(mock)
	ctx := context.Background()
	tokenID := "token-1"

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`UPDATE security_tokens`).
			WithArgs(tokenID).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.MarkUsed(ctx, nil, tokenID)
		assert.NoError(t, err)
	})
}

func TestPostgresSecurityEventRepository_Create(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresSecurityEventRepository(mock)
	ctx := context.Background()

	event := &model.SecurityEvent{
		UserID:    ptr("user-1"),
		EventType: "auth.password_reset_requested",
		Severity:  "info",
		Details:   "details",
		IPAddress: "127.0.0.1",
		UserAgent: "ua",
	}

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(`INSERT INTO security_events`).
			WithArgs(event.UserID, event.TenantID, event.EventType, event.Severity, event.Details, event.IPAddress, event.UserAgent).
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).
				AddRow("event-1", time.Now()))

		err := repo.Create(ctx, event)
		assert.NoError(t, err)
		assert.Equal(t, "event-1", event.ID)
	})
}

func ptr[T any](v T) *T {
	return &v
}
