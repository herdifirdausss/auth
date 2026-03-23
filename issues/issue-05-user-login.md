# Issue #05: User Login (POST /auth/login)

## Labels
`feature`, `auth`, `priority:critical`, `api`, `security`

## Branch
`feature/user-login`

## Description
Implementasi endpoint login lengkap dengan rate limiting (Redis), password verification (argon2id), brute-force protection (auto-suspend setelah 10 failed attempts), session creation, refresh token generation, JWT access token, dan Redis session caching.

## Prerequisites
- Issue #01 (Database Migration) ✅
- Issue #02 (Redis & Rate Limiting) ✅
- Issue #03 (User Registration) ✅
- Issue #04 (Email Verification) ✅

## API Specification

### Request
```
POST /auth/login
Content-Type: application/json

{
  "email": "string (required)",
  "password": "string (required)",
  "device_fingerprint": "string (required)",
  "device_name": "string (optional)"
}

Headers:
  X-Forwarded-For: <client IP>
  User-Agent: <browser/client UA>
```

### Response — Success (200)
```json
{
  "status": "success",
  "data": {
    "access_token": "<JWT>",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```
+ `Set-Cookie: refresh_token=<raw>; HttpOnly; Secure; SameSite=Strict; Path=/auth; Max-Age=2592000`

### Response — MFA Required (200)
```json
{
  "status": "success",
  "data": {
    "mfa_required": true,
    "mfa_token": "<short-lived JWT, 5min>"
  }
}
```

### Response — Rate Limited (429)
```json
{
  "status": "error",
  "message": "Too many login attempts. Please try again later.",
  "retry_after": 900
}
```

### Response — Account Suspended (403)
```json
{
  "status": "error",
  "message": "Account has been suspended due to too many failed login attempts"
}
```

### Response — Unauthorized (401)
```json
{
  "status": "error",
  "message": "Invalid email or password"
}
```

## Implementation Steps

### Step 1: JWT Utility
**File:** `internal/security/jwt.go`
```
type JWTConfig struct {
    SecretKey     string
    Issuer        string
    AccessExpiry  time.Duration // 15 minutes
}

type JWTClaims struct {
    Sub       string   `json:"sub"`      // user_id
    Sid       string   `json:"sid"`      // session_id
    Tid       string   `json:"tid"`      // tenant_id
    Roles     []string `json:"roles"`
    jwt.RegisteredClaims
}

func GenerateAccessToken(config JWTConfig, claims JWTClaims) (string, error)
func ValidateAccessToken(config JWTConfig, tokenString string) (*JWTClaims, error)
func GenerateMFAToken(config JWTConfig, userID string, expiry time.Duration) (string, error)
```

### Step 2: Repository Extensions
**File:** `internal/repository/credential_repository.go` (extend)
```
func FindByUserID(ctx context.Context, userID string) (*model.UserCredential, error)
```

**File:** `internal/repository/session_repository.go`
```
type SessionRepository interface {
    Create(ctx context.Context, session *model.Session) error
    FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
}
```

**File:** `internal/repository/refresh_token_repository.go`
```
type RefreshTokenRepository interface {
    Create(ctx context.Context, token *model.RefreshToken) error
}
```

**File:** `internal/repository/mfa_repository.go`
```
type MFARepository interface {
    FindPrimaryActive(ctx context.Context, userID string) (*model.MFAMethod, error)
}
```

**File:** `internal/repository/membership_repository.go` (extend)
```
func FindActiveByUserID(ctx context.Context, userID string) (*model.TenantMembership, error)
```

**File:** `internal/repository/user_repository.go` (extend)
```
func IncrementFailedLogin(ctx context.Context, userID string) error
func SuspendUser(ctx context.Context, userID string) error
func ResetFailedLoginAndUpdateLastLogin(ctx context.Context, userID string, ip string) error
```

### Step 3: Service Layer
**File:** `internal/service/auth_service.go` (extend)
```
func Login(ctx context.Context, req *model.LoginRequest, ip string, userAgent string) (*model.LoginResponse, error)

Flow:
1. Rate limit: rateLimiter.Check("rate_limit:login:{ip}", 20, 15m)
2. Rate limit: rateLimiter.Check("rate_limit:login_user:{lower(email)}", 10, 15m)
3. FindByEmail → jika tidak ada → 401 generic
4. Cek is_suspended → 403
5. FindByUserID (credentials) → verify argon2id
6. Jika gagal:
   a. IncrementFailedLogin
   b. Jika failed_count >= 10 → SuspendUser
   c. Log security event 'auth.login_failed'
   d. Return 401
7. Jika berhasil:
   a. ResetFailedLoginAndUpdateLastLogin
   b. FindActiveByUserID (membership)
   c. FindPrimaryActive (MFA) → jika ada: return MFA required
   d. Create session (token_hash dari raw token)
   e. Create refresh token (family_id baru, generation=1)
   f. Generate JWT access token
   g. Cache session ke Redis
   h. Log security event 'auth.login_success'
   i. Return access_token + refresh_token (cookie)
```

### Step 4: Handler
**File:** `internal/handler/auth_handler.go` (extend)
```
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request)
- Parse body
- Extract IP dari X-Forwarded-For atau RemoteAddr
- Extract User-Agent dari header
- Call authService.Login()
- Set refresh_token sebagai HttpOnly cookie
- Return JSON response
```

### Step 5: Route
```
POST /auth/login → authHandler.Login
```

## Testing Requirements (100% Coverage)

### JWT Tests
**File:** `internal/security/jwt_test.go`
```go
func TestGenerateAccessToken_Success(t *testing.T)
func TestGenerateAccessToken_ContainsClaims(t *testing.T)
func TestValidateAccessToken_Valid(t *testing.T)
func TestValidateAccessToken_Expired(t *testing.T)
func TestValidateAccessToken_InvalidSignature(t *testing.T)
func TestValidateAccessToken_MalformedToken(t *testing.T)
func TestGenerateMFAToken_Success(t *testing.T)
func TestGenerateMFAToken_ShortExpiry(t *testing.T)
```

### Repository Tests
```go
func TestCredentialRepo_FindByUserID_Found(t *testing.T)
func TestCredentialRepo_FindByUserID_NotFound(t *testing.T)
func TestSessionRepo_Create_Success(t *testing.T)
func TestRefreshTokenRepo_Create_Success(t *testing.T)
func TestMFARepo_FindPrimaryActive_Found(t *testing.T)
func TestMFARepo_FindPrimaryActive_NotFound(t *testing.T)
func TestMembershipRepo_FindActiveByUserID_Found(t *testing.T)
func TestUserRepo_IncrementFailedLogin_Success(t *testing.T)
func TestUserRepo_SuspendUser_Success(t *testing.T)
func TestUserRepo_ResetFailedLogin_Success(t *testing.T)
```

### Service Tests
```go
func TestLogin_Success(t *testing.T)
func TestLogin_InvalidEmail(t *testing.T)
func TestLogin_InvalidPassword(t *testing.T)
func TestLogin_AccountSuspended(t *testing.T)
func TestLogin_RateLimited_ByIP(t *testing.T)
func TestLogin_RateLimited_ByUser(t *testing.T)
func TestLogin_BruteForce_AutoSuspend(t *testing.T)
func TestLogin_MFARequired(t *testing.T)
func TestLogin_WithTenant(t *testing.T)
func TestLogin_SessionCreated(t *testing.T)
func TestLogin_RefreshTokenCreated(t *testing.T)
func TestLogin_JWTGenerated(t *testing.T)
func TestLogin_RedisCached(t *testing.T)
func TestLogin_SecurityEventLogged_Success(t *testing.T)
func TestLogin_SecurityEventLogged_Failed(t *testing.T)
func TestLogin_GenericErrorMessage(t *testing.T)  // anti-enumeration
func TestLogin_FailedCountIncrement(t *testing.T)
func TestLogin_FailedCountReset_OnSuccess(t *testing.T)
func TestLogin_DBError(t *testing.T)
```

### Handler Tests
```go
func TestLoginHandler_Success_200(t *testing.T)
func TestLoginHandler_SetCookie_RefreshToken(t *testing.T)
func TestLoginHandler_InvalidJSON_400(t *testing.T)
func TestLoginHandler_Unauthorized_401(t *testing.T)
func TestLoginHandler_Suspended_403(t *testing.T)
func TestLoginHandler_RateLimited_429(t *testing.T)
func TestLoginHandler_InternalError_500(t *testing.T)
func TestLoginHandler_MFARequired_200(t *testing.T)
```

## Security Notes
- ⚠️ Pesan error HARUS generic: "Invalid email or password" — JANGAN "email not found" vs "wrong password"
- ⚠️ Rate limit: max 20/IP/15min, max 10/user/15min
- ⚠️ Auto-suspend setelah 10 failed login attempts
- ⚠️ Refresh token di HttpOnly Secure SameSite=Strict cookie
- ⚠️ JWT access token short-lived: 15 menit
- ⚠️ Raw token JANGAN disimpan ke DB, simpan hash saja
- ⚠️ Session idle timeout: 30 menit
- ⚠️ Session absolute expiry: 7 hari

## Definition of Done
- [ ] Endpoint POST /auth/login berfungsi
- [ ] Rate limiting berjalan (IP + user-based)
- [ ] Password verification dengan argon2id
- [ ] Auto-suspend setelah 10 failed attempts
- [ ] Session + refresh token ter-create
- [ ] JWT access token ter-generate
- [ ] Session ter-cache di Redis
- [ ] Refresh token di HttpOnly cookie
- [ ] MFA check (return mfa_required jika ada)
- [ ] Security events ter-log
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
