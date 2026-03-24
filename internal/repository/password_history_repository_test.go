package repository

import (
	"context"
	"testing"


	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
)

func TestPostgresPasswordHistoryRepository_GetRecentPasswords(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresPasswordHistoryRepository(mock)
	ctx := context.Background()
	userID := "user-1"
	limit := 5

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(`SELECT password_hash FROM user_password_history WHERE user_id = \$1`).
			WithArgs(userID, limit).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash"}).
				AddRow("hash-1").
				AddRow("hash-2"))

		hashes, err := repo.GetRecentPasswords(ctx, userID, limit)
		assert.NoError(t, err)
		assert.Len(t, hashes, 2)
		assert.Equal(t, "hash-1", hashes[0])
	})
}

func TestPostgresPasswordHistoryRepository_Create(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresPasswordHistoryRepository(mock)
	ctx := context.Background()
	userID := "user-1"
	hash := "hash-1"

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO user_password_history`).
			WithArgs(userID, hash).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Create(ctx, nil, userID, hash)
		assert.NoError(t, err)
	})
}

func TestPostgresPasswordHistoryRepository_Cleanup(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresPasswordHistoryRepository(mock)
	ctx := context.Background()
	userID := "user-1"
	keepCount := 5

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM user_password_history WHERE id IN`).
			WithArgs(userID, keepCount).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Cleanup(ctx, userID, keepCount)
		assert.NoError(t, err)
	})
}
