# Issue #06: Token Validation Middleware

## Labels
`feature`, `auth`, `middleware`, `priority:critical`, `security`

## Branch
`feature/token-validation-middleware`

## Description
Implementasi middleware untuk memvalidasi JWT access token di setiap protected endpoint. Middleware ini mengecek JWT signature, mengambil session dari Redis cache (atau DB jika cache miss), memvalidasi idle timeout, dan meng-set request context.

## Prerequisites
- Issue #02 (Redis & Rate Limiting) ✅
- Issue #05 (User Login) ✅

## Middleware Flow
```
1. Extract Bearer token dari Authorization header
2. Verify JWT signature + expiry
3. Ambil session_id (sid) dari JWT payload
4. token_hash = SHA256(bearer_token)
5. Cek Redis cache: GET session:cache:{token_hash}
   → Jika HIT: gunakan data dari cache
6. Jika MISS:
   → Query DB: sessions WHERE token_hash AND NOT revoked AND NOT expired
7. Jika session tidak ada → 401
8. Cek idle timeout: idle_timeout_at < now() → 401 + revoke session
9. Update last_activity (debounce: hanya jika >5min dari update terakhir)
10. Cache result ke Redis (TTL 5 menit)
11. Set request context: { user_id, tenant_id, session_id, mfa_verified }
```

## Implementation Steps

### Step 1: Auth Context
**File:** `internal/middleware/context.go`
```
type AuthContext struct {
    UserID      string
    TenantID    string
    SessionID   string
    MFAVerified bool
    TokenHash   string
}

func SetAuthContext(ctx context.Context, auth *AuthContext) context.Context
func GetAuthContext(ctx context.Context) (*AuthContext, error)
```

### Step 2: Auth Middleware
**File:** `internal/middleware/auth_middleware.go`
```
type AuthMiddleware struct {
    jwtConfig      *security.JWTConfig
    sessionRepo    repository.SessionRepository
    sessionCache   *redis.SessionCache
}

func NewAuthMiddleware(...) *AuthMiddleware

func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler
  - Extract token: "Bearer <token>"
  - Validate JWT
  - Hash token
  - Check cache → check DB if miss
  - Validate session: expired? revoked? idle timeout?
  - Debounced activity update
  - Set auth context
  - Call next
```

### Step 3: Session Repository Extension
**File:** `internal/repository/session_repository.go` (extend)
```
func FindActiveByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
  - covering index query
  - WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()

func RevokeSession(ctx context.Context, sessionID string, reason string) error
  - UPDATE sessions SET revoked_at = now(), revoked_reason = $2

func UpdateActivity(ctx context.Context, sessionID string) error
  - UPDATE sessions SET last_activity_at = now(), idle_timeout_at = now() + interval '30 minutes'
```

### Step 4: Helper Functions
**File:** `internal/middleware/helpers.go`
```
func extractBearerToken(r *http.Request) (string, error)
func shouldUpdateActivity(lastActivity time.Time) bool // >5 min check
func writeUnauthorized(w http.ResponseWriter, message string)
```

### Step 5: Route Integration
```
Semua protected routes harus di-wrap: authMiddleware.Authenticate(protectedHandler)
```

## Testing Requirements (100% Coverage)

### Context Tests
**File:** `internal/middleware/context_test.go`
```go
func TestSetAuthContext_Success(t *testing.T)
func TestGetAuthContext_Success(t *testing.T)
func TestGetAuthContext_NotSet(t *testing.T)
```

### Middleware Tests
**File:** `internal/middleware/auth_middleware_test.go`
```go
func TestAuth_ValidToken_CacheHit(t *testing.T)
func TestAuth_ValidToken_CacheMiss_DBHit(t *testing.T)
func TestAuth_NoAuthHeader(t *testing.T)
func TestAuth_InvalidBearerFormat(t *testing.T)
func TestAuth_ExpiredJWT(t *testing.T)
func TestAuth_InvalidJWTSignature(t *testing.T)
func TestAuth_SessionNotFound(t *testing.T)
func TestAuth_SessionRevoked(t *testing.T)
func TestAuth_SessionExpired(t *testing.T)
func TestAuth_IdleTimeout_Exceeded(t *testing.T)
func TestAuth_IdleTimeout_RevokesSession(t *testing.T)
func TestAuth_ActivityUpdate_Debounced(t *testing.T)       // <5min → no update
func TestAuth_ActivityUpdate_Applied(t *testing.T)         // >5min → update
func TestAuth_CacheSetAfterDBQuery(t *testing.T)
func TestAuth_ContextSetCorrectly(t *testing.T)
func TestAuth_RedisDown_FallbackToDB(t *testing.T)
```

### Helper Tests
**File:** `internal/middleware/helpers_test.go`
```go
func TestExtractBearerToken_Valid(t *testing.T)
func TestExtractBearerToken_Missing(t *testing.T)
func TestExtractBearerToken_WrongScheme(t *testing.T)
func TestExtractBearerToken_Empty(t *testing.T)
func TestShouldUpdateActivity_Under5Min(t *testing.T)
func TestShouldUpdateActivity_Over5Min(t *testing.T)
func TestShouldUpdateActivity_Exactly5Min(t *testing.T)
```

## Security Notes
- ⚠️ JWT verification HARUS check signature + expiry
- ⚠️ Session lookup pakai covering index (no heap access)
- ⚠️ Idle timeout auto-revoke session
- ⚠️ Activity update debounced (max 1x per 5min) untuk mengurangi DB writes
- ⚠️ Graceful fallback: jika Redis down → langsung query DB
- ⚠️ Jangan expose detail error ke client: selalu 401 generic

## Definition of Done
- [ ] Middleware authenticate request dengan JWT
- [ ] Redis cache hit path berfungsi
- [ ] DB fallback saat cache miss
- [ ] Idle timeout terdeteksi dan session di-revoke
- [ ] Activity update terdebounce
- [ ] Auth context terset di request
- [ ] Graceful saat Redis down
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
