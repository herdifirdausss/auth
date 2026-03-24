# Issue #09: Password Reset Flow (Forgot + Reset)

## Labels
`feature`, `auth`, `security`, `priority:high`, `api`

## Branch
`feature/password-reset`

## Description
Implementasi flow password reset: forgot-password (request reset link) dan reset-password (actually set new password). Termasuk distributed lock (anti-spam), password history check, session revocation.

## Prerequisites
- Issue #02 (Redis & Rate Limiting) ✅
- Issue #03 (User Registration) ✅

## API Specification

### POST /auth/forgot-password
**Request:** `{ "email": "user@example.com" }`
**Response (200):** `{ "status": "success", "message": "If the email exists, you'll receive a reset link" }`

> ⚠️ SELALU return 200 regardless apakah email ada atau tidak (anti-enumeration)

### POST /auth/reset-password
**Request:** `{ "token": "<raw_token>", "new_password": "<new_password>" }`
**Response (200):** `{ "status": "success", "message": "Password has been reset successfully" }`
**Response (400):** `{ "status": "error", "message": "Invalid or expired token" }`
**Response (400):** `{ "status": "error", "message": "Password has been recently used" }`

## Implementation Steps

### Step 1: Repository Extensions
**File:** `internal/repository/password_history_repository.go`
```
- GetRecentPasswords(ctx, userID string, limit int) ([]string, error)
  → SELECT password_hash ORDER BY created_at DESC LIMIT 5
- Create(ctx, userID, passwordHash string) error
- Cleanup(ctx, userID string, keepCount int) error
  → DELETE old entries beyond keepCount
```

**File:** `internal/repository/credential_repository.go` (extend)
```
- UpdatePassword(ctx, tx *sql.Tx, userID, hash, salt string) error
  → UPDATE user_credentials SET password_hash, password_salt, last_changed_at, change_count+1
```

**File:** `internal/repository/session_repository.go` (extend)
```
- RevokeAllByUser(ctx, tx *sql.Tx, userID, reason string) error
  → UPDATE sessions SET revoked_at=now(), revoked_reason WHERE user_id AND revoked_at IS NULL
```

### Step 2: Service Layer
**File:** `internal/service/auth_service.go` (extend)

**ForgotPassword:**
1. Distributed lock: `SET NX lock:password_reset:{email} EX 60` → jika gagal → return 200
2. FindByEmail → jika tidak ada → return 200 (anti-enumeration)
3. Generate token → hash → INSERT security_tokens (type='password_reset', expires=1h)
4. TODO: send email (log dulu)
5. Return 200

**ResetPassword:**
1. Hash token → FindValidToken(hash, 'password_reset')
2. Jika tidak ada → 400
3. Validate password complexity
4. Check password history: verify new password against last 5 hashes → if match → 400
5. Hash new password (argon2id)
6. BEGIN transaction:
   a. UpdatePassword
   b. INSERT password_history
   c. Cleanup old password_history
   d. MarkUsed(token)
   e. RevokeAllByUser(sessions, 'password_reset')
7. COMMIT
8. Log security event 'auth.password_reset'

### Step 3: Handler & Routes
```
POST /auth/forgot-password → authHandler.ForgotPassword
POST /auth/reset-password  → authHandler.ResetPassword
```

## Testing Requirements (100% Coverage)

### Repository Tests
```go
TestPasswordHistoryRepo_GetRecent_Found, TestPasswordHistoryRepo_GetRecent_Empty
TestPasswordHistoryRepo_Create_Success, TestPasswordHistoryRepo_Cleanup
TestCredentialRepo_UpdatePassword_Success
TestSessionRepo_RevokeAllByUser_Success, TestSessionRepo_RevokeAllByUser_NoSessions
```

### Service Tests
```go
TestForgotPassword_Success, TestForgotPassword_EmailNotFound_StillReturns200
TestForgotPassword_DistributedLock_Blocks, TestForgotPassword_TokenGenerated
TestResetPassword_Success, TestResetPassword_InvalidToken
TestResetPassword_ExpiredToken, TestResetPassword_WeakPassword
TestResetPassword_PasswordRecentlyUsed
TestResetPassword_AllSessionsRevoked, TestResetPassword_PasswordHistoryUpdated
TestResetPassword_OldHistoryCleaned, TestResetPassword_DBError_Rollback
TestResetPassword_SecurityEventLogged
```

### Handler Tests
```go
TestForgotPasswordHandler_200_Always
TestResetPasswordHandler_Success_200
TestResetPasswordHandler_InvalidToken_400
TestResetPasswordHandler_WeakPassword_400
TestResetPasswordHandler_PasswordReused_400
TestResetPasswordHandler_InternalError_500
```

## Security Notes
- ⚠️ SELALU return 200 pada forgot-password (anti-enumeration)
- ⚠️ Distributed lock: 60 detik cooldown per email
- ⚠️ Password history: cek 5 password terakhir
- ⚠️ Revoke SEMUA sessions setelah password reset
- ⚠️ Token valid 1 jam, single-use

## Definition of Done
- [ ] Forgot password + reset password endpoints berfungsi
- [ ] Anti-enumeration (selalu 200)
- [ ] Distributed lock berfungsi
- [ ] Password history check (last 5)
- [ ] All sessions revoked on reset
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
