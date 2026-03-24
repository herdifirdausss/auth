package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/herdifirdausss/auth/internal/service"
	"log/slog"
	"github.com/herdifirdausss/auth/internal/infrastructure/redis"
	"github.com/alicebob/miniredis/v2"
	redisLib "github.com/redis/go-redis/v9"
)

func TestPasswordRecovery_Integration(t *testing.T) {
	// Setup Mini Redis
	mr, _ := miniredis.Run()
	defer mr.Close()
	redisClient := redisLib.NewClient(&redisLib.Options{Addr: mr.Addr()})
	rateLimiter := redis.NewRateLimiter(redisClient)

	setup := func(t *testing.T) (pgxmock.PgxPoolIface, *AuthHandler) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		
		userRepo := repository.NewPostgresUserRepository(mock)
		credRepo := repository.NewPostgresCredentialRepository(mock)
		tokenRepo := repository.NewPostgresSecurityTokenRepository(mock)
		eventRepo := repository.NewPostgresSecurityEventRepository(mock)
		historyRepo := repository.NewPostgresPasswordHistoryRepository(mock)
		sessionRepo := repository.NewPostgresSessionRepository(mock)

		authService := service.NewAuthService(
			mock, userRepo, credRepo, tokenRepo, eventRepo, 
			nil, nil, sessionRepo, nil, nil, historyRepo,
			security.NewArgon2idHasher(), rateLimiter, nil, 
			security.JWTConfig{}, slog.Default(),
		)

		return mock, NewAuthHandler(authService, slog.Default())
	}

	t.Run("ForgotPassword_UserEnumeration_Timing", func(t *testing.T) {
		mock, h := setup(t)
		defer mock.Close()

		email := "target@example.com"
		reqBody, _ := json.Marshal(model.ForgotPasswordRequest{Email: email})

		// Case 1: User Exists
		mock.ExpectQuery(`SELECT (.+) FROM users WHERE LOWER\(email\) = LOWER\(\$1\)`).
			WithArgs(email).
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "username", "is_active", "is_verified", "is_suspended", "failed_login_count", "created_at", "updated_at"}).
				AddRow("user-1", email, "target", true, true, false, 0, time.Now(), time.Now()))
		mock.ExpectQuery(`INSERT INTO security_tokens`).
			WithArgs("user-1", "password_reset", pgxmock.AnyArg(), pgxmock.AnyArg(), "127.0.0.1", "ua").
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("token-1", time.Now()))
		mock.ExpectQuery(`INSERT INTO security_events`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), "auth.password_reset_requested", "info", "Password reset requested", "127.0.0.1", "ua").
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("event-1", time.Now()))

		w1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewBuffer(reqBody))
		req1.RemoteAddr = "127.0.0.1:12345"
		req1.Header.Set("User-Agent", "ua")
		h.ForgotPassword(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		// Case 2: User Not Exists
		email2 := "unknown@example.com"
		reqBody2, _ := json.Marshal(model.ForgotPasswordRequest{Email: email2})
		mock.ExpectQuery(`SELECT (.+) FROM users WHERE LOWER\(email\) = LOWER\(\$1\)`).
			WithArgs(email2).
			WillReturnRows(pgxmock.NewRows([]string{"id", "email", "username", "is_active", "is_verified", "is_suspended", "failed_login_count", "created_at", "updated_at"}))

		w2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewBuffer(reqBody2))
		req2.RemoteAddr = "127.0.0.1:12345"
		req2.Header.Set("User-Agent", "ua")
		h.ForgotPassword(w2, req2)
		assert.Equal(t, http.StatusOK, w2.Code)

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ResetPassword_FullFlow", func(t *testing.T) {
		mock, h := setup(t)
		defer mock.Close()

		rawToken := "valid-reset-token"
		tokenHash := security.HashToken(rawToken)
		newPassword := "NewSecurePassword123!"

		reqBody, _ := json.Marshal(model.ResetPasswordRequest{
			Token:       rawToken,
			NewPassword: newPassword,
		})

		// 1. Find Valid Token
		mock.ExpectQuery(`SELECT (.+) FROM security_tokens WHERE token_hash = \$1`).
			WithArgs(tokenHash, "password_reset").
			WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "token_type", "token_hash", "expires_at", "used_at", "ip_address", "user_agent", "created_at"}).
				AddRow("token-1", "user-1", "password_reset", tokenHash, time.Now().Add(time.Hour), nil, "127.0.0.1", "ua", time.Now()))

		// 2. Check History
		mock.ExpectQuery(`SELECT password_hash, password_salt FROM password_history WHERE user_id = \$1`).
			WithArgs("user-1", 5).
			WillReturnRows(pgxmock.NewRows([]string{"password_hash", "password_salt"}))

		// 3. Transaction
		mock.ExpectBegin()
		mock.ExpectExec(`UPDATE user_credentials`).
			WithArgs("user-1", pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec(`INSERT INTO password_history`).
			WithArgs("user-1", pgxmock.AnyArg(), pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectExec(`DELETE FROM password_history WHERE id IN`).
			WithArgs("user-1", 5).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		mock.ExpectExec(`UPDATE security_tokens SET used_at = now\(\)`).
			WithArgs("token-1").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectExec(`UPDATE sessions SET revoked_at = now\(\)`).
			WithArgs("user-1", "password_reset").
			WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectCommit()

		// 4. Security Event
		mock.ExpectQuery(`INSERT INTO security_events`).
			WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), "auth.password_reset_success", "info", "Password reset successful", "127.0.0.1", "ua").
			WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("event-2", time.Now()))

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewBuffer(reqBody))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("User-Agent", "ua")
		h.ResetPassword(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "Password has been reset successfully")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

