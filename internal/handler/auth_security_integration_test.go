package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"log/slog"

	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/repository"
	"github.com/herdifirdausss/auth/internal/security"
	"github.com/herdifirdausss/auth/internal/service"
	"github.com/herdifirdausss/auth/internal/utils"
	"github.com/herdifirdausss/auth/internal/mocks"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	infra "github.com/herdifirdausss/auth/internal/infrastructure/redis"
)

func setupTest(t *testing.T) (pgxmock.PgxPoolIface, service.AuthService, service.MFAService, *AuthHandler, *MFAHandler, func()) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}

	ctrl := gomock.NewController(t)
	mockRateLimiter := mocks.NewMockRateLimiter(ctrl)
	mockSessionCache := mocks.NewMockSessionCache(ctrl)
	mockAuditService := mocks.NewMockAuditService(ctrl)

	// Default behaviors for mocks to avoid panic
	mockRateLimiter.EXPECT().Check(gomock.Any(), gomock.Any()).Return(infra.RateLimitResult{Allowed: true}, nil).AnyTimes()
	mockRateLimiter.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockSessionCache.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockSessionCache.EXPECT().Get(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	mockSessionCache.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockAuditService.EXPECT().Log(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	mockAuditService.EXPECT().LogAction(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	userRepo := repository.NewPostgresUserRepository(mock)
	credRepo := repository.NewPostgresCredentialRepository(mock)
	tokenRepo := repository.NewPostgresSecurityTokenRepository(mock)
	eventRepo := repository.NewPostgresSecurityEventRepository(mock)
	tenantRepo := repository.NewPostgresTenantRepository(mock)
	membershipRepo := repository.NewPostgresTenantMembershipRepository(mock)
	sessionRepo := repository.NewPostgresSessionRepository(mock)
	rfRepo := repository.NewPostgresRefreshTokenRepository(mock)
	mfaRepo := repository.NewPostgresMFARepository(mock)
	historyRepo := repository.NewPostgresPasswordHistoryRepository(mock)
	trustedDeviceRepo := repository.NewPostgresTrustedDeviceRepository(mock)
	roleRepo := repository.NewPostgresRoleRepository(mock)
	membershipRoleRepo := repository.NewPostgresMembershipRoleRepository(mock)

	jwtCfg := security.JWTConfig{
		SecretKey:     []byte("test-secret-3Char-long-!!!-12345678"),
		Issuer:        "test",
		AccessExpiry:  15 * time.Minute,
	}

	mockRiskService := mocks.NewMockRiskService(ctrl)
	mockPwnedValidator := mocks.NewMockPwnedValidator(ctrl)

	// Default behaviors for new mocks
	mockPwnedValidator.EXPECT().IsPwned(gomock.Any(), gomock.Any()).Return(false, 0, nil).AnyTimes()
	mockRiskService.EXPECT().AnalyzeLoginRisk(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&model.RiskAssessment{Level: model.RiskLow}, nil).AnyTimes()

	authService := service.NewAuthService(
		mock, userRepo, credRepo, tokenRepo, eventRepo,
		tenantRepo, membershipRepo, sessionRepo, rfRepo, mfaRepo,
		historyRepo, trustedDeviceRepo, roleRepo, membershipRoleRepo,
		mockRiskService,
		mockPwnedValidator,
		mockAuditService,
		security.NewArgon2idHasher(), mockRateLimiter, mockSessionCache, jwtCfg, slog.Default(),
	)

	mfaService := service.NewMFAService(
		mock, mfaRepo, userRepo, sessionRepo, rfRepo, membershipRepo,
		jwtCfg, mockRateLimiter, mockSessionCache, trustedDeviceRepo, utils.RealClock{}, slog.Default(),
	)

	authHandler := NewAuthHandler(authService, slog.Default())
	mfaHandler := NewMFAHandler(mfaService, slog.Default())

	cleanup := func() {
		mock.Close()
		ctrl.Finish()
	}

	return mock, authService, mfaService, authHandler, mfaHandler, cleanup
}

func TestAuthSecurity_Integration(t *testing.T) {
	t.Run("Full_Lifecycle_Fingerprinting_And_MFA_Skip", func(t *testing.T) {
		mock, _, _, authHandler, mfaHandler, cleanup := setupTest(t)
		defer cleanup()

		email := "test@example.com"
		password := "SecurePass123!"
		fingerprint := "fp-123"
		
		// Correct Argon2id hash for "SecurePass123!" with "2c777fd2741b0a904536214e90766d76" salt
		testHash := "d0b0c8a3e598296bbeca351372e012fe942838ff9ce04378b8123463e988ad4b"
		testSalt := "2c777fd2741b0a904536214e90766d76"

		// 1. Register
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s).*FROM users.*`).WithArgs(email).WillReturnRows(pgxmock.NewRows([]string{}))
		mock.ExpectQuery(`(?s).*INSERT INTO tenants.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("ten-1", time.Now()))
		mock.ExpectQuery(`(?s).*INSERT INTO users.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow("user-1", time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*INSERT INTO user_credentials.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"created_at", "updated_at"}).AddRow(time.Now(), time.Now()))
		mock.ExpectExec(`(?s).*INSERT INTO password_history.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectQuery(`(?s).*INSERT INTO tenant_memberships.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow("mem-1", time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*FROM roles.*`).WithArgs("admin").WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "name", "description", "permissions", "is_system", "created_at", "updated_at"}).AddRow("role-admin", nil, "admin", "Admin", []string{"*"}, true, time.Now(), time.Now()))
		mock.ExpectExec(`(?s).*INSERT INTO membership_roles.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()
		
		mock.ExpectQuery(`(?s).*INSERT INTO security_tokens.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("tok-1", time.Now()))

		regBody, _ := json.Marshal(model.RegisterRequest{Email: email, Password: password, Username: "testuser", TenantSlug: "test-org"})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(regBody))
		req.Header.Set("X-Device-Fingerprint", fingerprint)
		authHandler.Register(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code, "Register failed: %s", rr.Body.String())

		// 2. Login - Returns MFA Required
		mock.ExpectQuery(`(?s).*FROM users.*`).WithArgs(email).WillReturnRows(pgxmock.NewRows([]string{"id", "email", "username", "phone", "is_active", "is_verified", "is_suspended", "failed_login_count", "last_login_at", "last_login_ip", "password_changed_at", "metadata", "created_at", "updated_at"}).
			AddRow("user-1", email, "testuser", nil, true, true, false, 0, nil, nil, nil, make(map[string]interface{}), time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*FROM user_credentials.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"user_id", "password_hash", "password_salt", "password_algo", "must_change_password", "last_changed_at", "created_at", "updated_at"}).AddRow("user-1", testHash, testSalt, "argon2id", false, time.Now(), time.Now(), time.Now())) 
		mock.ExpectExec(`(?s).*UPDATE users.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectQuery(`(?s).*FROM tenant_memberships.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "tenant_id", "status", "created_at"}).AddRow("mem-1", "user-1", "ten-1", "active", time.Now()))
		mock.ExpectQuery(`(?s).*FROM mfa_methods.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "method_type", "method_name", "secret_encrypted", "backup_codes_encrypted", "is_active", "is_primary", "last_used_at", "created_at", "updated_at"}).AddRow("mfa-1", "user-1", "totp", "TOTP", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==", "", true, true, nil, time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*FROM trusted_devices.*`).WithArgs("user-1", fingerprint).WillReturnRows(pgxmock.NewRows([]string{}))

		loginBody, _ := json.Marshal(model.LoginRequest{Email: email, Password: password, DeviceFingerprint: fingerprint})
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(loginBody))
		req.Header.Set("X-Device-Fingerprint", fingerprint)
		authHandler.Login(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "Login failed: %s", rr.Body.String())
		
		var wrapper struct {
			Data model.LoginResponse `json:"data"`
		}
		json.NewDecoder(rr.Body).Decode(&wrapper)
		loginRes := wrapper.Data
		assert.True(t, loginRes.MFARequired)

		// 3. MFA Challenge
		mock.ExpectQuery(`(?s).*FROM mfa_methods.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "method_type", "method_name", "secret_encrypted", "backup_codes_encrypted", "is_active", "is_primary", "last_used_at", "created_at", "updated_at"}).AddRow("mfa-1", "user-1", "totp", "TOTP", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==", "", true, true, nil, time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*FROM tenant_memberships.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "tenant_id", "status", "created_at"}).AddRow("mem-1", "user-1", "ten-1", "active", time.Now()))
		mock.ExpectBegin()
		mock.ExpectExec(`(?s).*UPDATE mfa_methods.*`).WithArgs(pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectQuery(`(?s).*INSERT INTO sessions.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow("sess-1", time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*INSERT INTO refresh_tokens.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("rt-1", time.Now()))
		mock.ExpectQuery(`(?s).*INSERT INTO trusted_devices.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("td-1", time.Now()))
		mock.ExpectCommit()

		challengeBody, _ := json.Marshal(model.ChallengeRequest{MFAToken: loginRes.MFAToken, OTPCode: "000000", TrustDevice: true})
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/auth/mfa/challenge", bytes.NewBuffer(challengeBody))
		req.Header.Set("X-Device-Fingerprint", fingerprint)
		os.Setenv("MFA_TEST_MODE", "true")
		mfaHandler.Challenge(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "Challenge failed: %s", rr.Body.String())

		// 4. MFA Skip Login
		mock.ExpectQuery(`(?s).*FROM users.*`).WithArgs(email).WillReturnRows(pgxmock.NewRows([]string{"id", "email", "username", "phone", "is_active", "is_verified", "is_suspended", "failed_login_count", "last_login_at", "last_login_ip", "password_changed_at", "metadata", "created_at", "updated_at"}).
			AddRow("user-1", email, "testuser", nil, true, true, false, 0, nil, nil, nil, make(map[string]interface{}), time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*FROM user_credentials.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"user_id", "password_hash", "password_salt", "password_algo", "must_change_password", "last_changed_at", "created_at", "updated_at"}).AddRow("user-1", testHash, testSalt, "argon2id", false, time.Now(), time.Now(), time.Now())) 
		mock.ExpectExec(`(?s).*UPDATE users.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
		mock.ExpectQuery(`(?s).*FROM tenant_memberships.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "tenant_id", "status", "created_at"}).AddRow("mem-1", "user-1", "ten-1", "active", time.Now()))
		mock.ExpectQuery(`(?s).*FROM mfa_methods.*`).WithArgs("user-1").WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "method_type", "method_name", "secret_encrypted", "backup_codes_encrypted", "is_active", "is_primary", "last_used_at", "created_at", "updated_at"}).AddRow("mfa-1", "user-1", "totp", "TOTP", "c2VjcmV0", "", true, true, nil, time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*FROM trusted_devices.*`).WithArgs("user-1", fingerprint).WillReturnRows(pgxmock.NewRows([]string{"id", "user_id", "device_fingerprint", "device_name", "device_type", "trust_level", "last_used_at", "expires_at", "created_at"}).AddRow("td-1", "user-1", fingerprint, "Device", "browser", 1, time.Now(), time.Now().Add(30*24*time.Hour), time.Now()))
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s).*INSERT INTO sessions.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow("sess-2", time.Now(), time.Now()))
		mock.ExpectQuery(`(?s).*INSERT INTO refresh_tokens.*`).WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnRows(pgxmock.NewRows([]string{"id", "created_at"}).AddRow("rt-2", time.Now()))
		mock.ExpectCommit()

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(loginBody))
		req.Header.Set("X-Device-Fingerprint", fingerprint)
		authHandler.Login(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "Skip-Login failed: %s", rr.Body.String())
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
