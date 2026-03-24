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
		mock.ExpectQuery(`SELECT password_hash, password_salt FROM password_history WHERE user_id = \$1`).
			WithArgs(userID, limit).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "password_salt"}).
				AddRow("hash-1", "salt-1").
				AddRow("hash-2", "salt-2"))

		history, err := repo.GetRecentPasswords(ctx, userID, limit)
		assert.NoError(t, err)
		assert.Len(t, history, 2)
		assert.Equal(t, "hash-1", history[0].PasswordHash)
		assert.Equal(t, "salt-1", history[0].PasswordSalt)
	})
}

func TestPostgresPasswordHistoryRepository_Create(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresPasswordHistoryRepository(mock)
	userID := "user-1"

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO password_history`).
			WithArgs(userID, "hash1", "salt1").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.Create(context.Background(), nil, userID, "hash1", "salt1")
		assert.NoError(t, err)

		mock.ExpectExec(`INSERT INTO password_history`).
			WithArgs(userID, "hash2", "salt2").
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err = repo.Create(context.Background(), nil, userID, "hash2", "salt2")
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
		mock.ExpectExec(`DELETE FROM password_history WHERE id IN`).
			WithArgs(userID, keepCount).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Cleanup(ctx, userID, keepCount)
		assert.NoError(t, err)
	})
}
