package repository

import (
	"context"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
)

func TestPostgresCredentialRepository_Create(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresCredentialRepository(mock)
	ctx := context.Background()

	cred := &model.UserCredential{
		UserID:       "user-1",
		PasswordHash: "hash",
		PasswordSalt: "salt",
		PasswordAlgo: "argon2id",
	}

	t.Run("SuccessWithoutTx", func(t *testing.T) {
		createdAt := time.Now()
		updatedAt := time.Now()

		mock.ExpectQuery(`INSERT INTO user_credentials`).
			WithArgs(cred.UserID, cred.PasswordHash, cred.PasswordSalt, cred.PasswordAlgo).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(createdAt, updatedAt))

		err := repo.Create(ctx, nil, cred)
		assert.NoError(t, err)
		assert.Equal(t, createdAt, cred.CreatedAt)
	})

	t.Run("SuccessWithTx", func(t *testing.T) {
		mock.ExpectBegin()
		tx, _ := mock.Begin(ctx)

		mock.ExpectQuery(`INSERT INTO user_credentials`).
			WithArgs(cred.UserID, cred.PasswordHash, cred.PasswordSalt, cred.PasswordAlgo).
			WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).
				AddRow(time.Now(), time.Now()))

		err := repo.Create(ctx, tx, cred)
		assert.NoError(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mock.ExpectQuery(`INSERT INTO user_credentials`).
			WithArgs(cred.UserID, cred.PasswordHash, cred.PasswordSalt, cred.PasswordAlgo).
			WillReturnError(assert.AnError)

		err := repo.Create(ctx, nil, cred)
		assert.Error(t, err)
	})
}

func TestPostgresCredentialRepository_FindByUserID(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresCredentialRepository(mock)
	ctx := context.Background()
	userID := "user-1"

	t.Run("Success", func(t *testing.T) {
		mock.ExpectQuery(`SELECT (.+) FROM user_credentials WHERE user_id = \$1`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"user_id", "password_hash", "password_salt", "password_algo", "must_change_password", "last_changed_at", "created_at", "updated_at"}).
				AddRow(userID, "hash", "salt", "argon2id", false, time.Now(), time.Now(), time.Now()))

		cred, err := repo.FindByUserID(ctx, userID)
		assert.NoError(t, err)
		assert.NotNil(t, cred)
		assert.Equal(t, userID, cred.UserID)
	})

	t.Run("NotFound", func(t *testing.T) {
		mock.ExpectQuery(`SELECT (.+) FROM user_credentials WHERE user_id = \$1`).
			WithArgs(userID).
			WillReturnRows(pgxmock.NewRows([]string{"id"}))

		cred, err := repo.FindByUserID(ctx, userID)
		assert.NoError(t, err)
		assert.Nil(t, cred)
	})
}

func TestPostgresCredentialRepository_UpdatePassword(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	repo := NewPostgresCredentialRepository(mock)
	ctx := context.Background()
	userID := "user-1"
	hash := "new-hash"
	salt := "new-salt"

	t.Run("Success", func(t *testing.T) {
		mock.ExpectExec(`UPDATE user_credentials`).
			WithArgs(userID, hash, salt).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))

		err := repo.UpdatePassword(ctx, nil, userID, hash, salt)
		assert.NoError(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mock.ExpectExec(`UPDATE user_credentials`).
			WithArgs(userID, hash, salt).
			WillReturnError(assert.AnError)

		err := repo.UpdatePassword(ctx, nil, userID, hash, salt)
		assert.Error(t, err)
	})
}
