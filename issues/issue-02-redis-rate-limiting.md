# Issue #02: Redis Configuration & Rate Limiting Utilities

## Labels
`infrastructure`, `redis`, `security`, `priority:critical`

## Branch
`feature/redis-rate-limiting`

## Description
Setup Redis client, connection pool, dan utility functions untuk rate limiting, session caching, CSRF token, dan distributed lock. Semua auth flow downstream bergantung pada modul ini.

## Prerequisites
- Redis 7+ terinstall dan running
- Issue #01 (Database Migration) sudah selesai

## Acceptance Criteria
- [ ] Redis client terkonfigurasi dengan connection pooling
- [ ] Rate limiter utility: generic, reusable, configurable
- [ ] Session cache utility: SET/GET/DEL dengan TTL
- [ ] CSRF utility: generate & validate
- [ ] Distributed lock utility: acquire & release
- [ ] Semua Redis key mengikuti naming convention
- [ ] Graceful degradation saat Redis down
- [ ] Unit test 100% coverage

## Redis Key Naming Convention
```
rate_limit:login:{ip}              → counter (INCR + EXPIRE 15m)
rate_limit:login_user:{user_id}    → counter (INCR + EXPIRE 15m)
rate_limit:otp:{user_id}           → counter (INCR + EXPIRE 10m)
session:cache:{token_hash}         → JSON string (SETEX 5m)
csrf:{session_id}                  → token string (SETEX 1h)
lock:password_reset:{user_id}      → "1" (SET NX EX 60)
```

## Implementation Steps

### Step 1: Redis Client Setup
**File:** `internal/infrastructure/redis/client.go`
```
- NewRedisClient(config RedisConfig) (*redis.Client, error)
- RedisConfig: Host, Port, Password, DB, PoolSize, MinIdleConns, DialTimeout, ReadTimeout, WriteTimeout
- Health check function: Ping()
- Graceful Close()
```

**File:** `config/redis.go`
```
- Load dari environment variables
- Defaults yang sensible untuk development
- Validation (host wajib, port wajib)
```

### Step 2: Rate Limiter
**File:** `internal/infrastructure/redis/rate_limiter.go`
```
type RateLimiter struct {
    client *redis.Client
}

type RateLimitConfig struct {
    Key       string
    MaxCount  int
    Window    time.Duration
}

type RateLimitResult struct {
    Allowed   bool
    Remaining int
    RetryAfter time.Duration
}

func (r *RateLimiter) Check(ctx context.Context, config RateLimitConfig) (RateLimitResult, error)
func (r *RateLimiter) Reset(ctx context.Context, key string) error
```

**Implementasi:**
1. `INCR {key}` → atomic increment
2. Jika counter == 1 (baru dibuat), `EXPIRE {key} {window_seconds}`
3. Jika counter > MaxCount → return `Allowed: false`
4. Return `Allowed: true` + `Remaining: MaxCount - counter`

### Step 3: Session Cache
**File:** `internal/infrastructure/redis/session_cache.go`
```
type SessionCache struct {
    client *redis.Client
    ttl    time.Duration // default: 5 minutes
}

type CachedSession struct {
    SessionID    string `json:"session_id"`
    UserID       string `json:"user_id"`
    TenantID     string `json:"tenant_id"`
    MFAVerified  bool   `json:"mfa_verified"`
    ExpiresAt    time.Time `json:"expires_at"`
    IdleTimeoutAt time.Time `json:"idle_timeout_at"`
}

func (s *SessionCache) Set(ctx context.Context, tokenHash string, session *CachedSession) error
func (s *SessionCache) Get(ctx context.Context, tokenHash string) (*CachedSession, error)
func (s *SessionCache) Delete(ctx context.Context, tokenHash string) error
```

### Step 4: Distributed Lock
**File:** `internal/infrastructure/redis/distributed_lock.go`
```
type DistributedLock struct {
    client *redis.Client
}

func (d *DistributedLock) Acquire(ctx context.Context, key string, ttl time.Duration) (bool, error)
func (d *DistributedLock) Release(ctx context.Context, key string) error
```

**Implementasi:**
- Acquire: `SET {key} "1" NX EX {ttl_seconds}` → return true jika berhasil
- Release: `DEL {key}`

### Step 5: CSRF Token Manager
**File:** `internal/infrastructure/redis/csrf.go`
```
type CSRFManager struct {
    client *redis.Client
    ttl    time.Duration // default: 1h
}

func (c *CSRFManager) Generate(ctx context.Context, sessionID string) (string, error)
func (c *CSRFManager) Validate(ctx context.Context, sessionID string, token string) (bool, error)
func (c *CSRFManager) Invalidate(ctx context.Context, sessionID string) error
```

## Testing Requirements (100% Coverage)

### Unit Tests (with Redis mock/miniredis)

**File:** `internal/infrastructure/redis/client_test.go`
```go
func TestNewRedisClient_Success(t *testing.T)
func TestNewRedisClient_InvalidConfig(t *testing.T)
func TestRedisClient_Ping_Success(t *testing.T)
func TestRedisClient_Ping_ConnectionError(t *testing.T)
func TestRedisClient_Close(t *testing.T)
```

**File:** `internal/infrastructure/redis/rate_limiter_test.go`
```go
func TestRateLimiter_Check_FirstRequest(t *testing.T)
func TestRateLimiter_Check_WithinLimit(t *testing.T)
func TestRateLimiter_Check_ExceedsLimit(t *testing.T)
func TestRateLimiter_Check_WindowExpired(t *testing.T)
func TestRateLimiter_Check_RetryAfter(t *testing.T)
func TestRateLimiter_Reset(t *testing.T)
func TestRateLimiter_Check_RedisError(t *testing.T)
func TestRateLimiter_Check_ConcurrentAccess(t *testing.T)
```

**File:** `internal/infrastructure/redis/session_cache_test.go`
```go
func TestSessionCache_Set_Success(t *testing.T)
func TestSessionCache_Get_Hit(t *testing.T)
func TestSessionCache_Get_Miss(t *testing.T)
func TestSessionCache_Delete_Success(t *testing.T)
func TestSessionCache_Get_Expired(t *testing.T)
func TestSessionCache_Set_InvalidData(t *testing.T)
func TestSessionCache_RedisError(t *testing.T)
```

**File:** `internal/infrastructure/redis/distributed_lock_test.go`
```go
func TestDistributedLock_Acquire_Success(t *testing.T)
func TestDistributedLock_Acquire_AlreadyLocked(t *testing.T)
func TestDistributedLock_Release_Success(t *testing.T)
func TestDistributedLock_Acquire_AfterExpiry(t *testing.T)
func TestDistributedLock_RedisError(t *testing.T)
```

**File:** `internal/infrastructure/redis/csrf_test.go`
```go
func TestCSRF_Generate_Success(t *testing.T)
func TestCSRF_Validate_Valid(t *testing.T)
func TestCSRF_Validate_Invalid(t *testing.T)
func TestCSRF_Validate_Expired(t *testing.T)
func TestCSRF_Invalidate(t *testing.T)
func TestCSRF_Generate_UniqueTokens(t *testing.T)
func TestCSRF_RedisError(t *testing.T)
```

## Security Notes
- ⚠️ Redis password wajib di production
- ⚠️ Gunakan TLS untuk koneksi Redis di production
- ⚠️ Jangan log Redis password atau token values
- ⚠️ Rate limiter harus atomic (gunakan INCR, bukan GET+SET)

## Definition of Done
- [ ] Redis client terhubung dan health check pass
- [ ] Rate limiter berfungsi dengan atomic operations
- [ ] Session cache SET/GET/DEL berfungsi dengan TTL
- [ ] Distributed lock prevent concurrent access
- [ ] CSRF token generate & validate berfungsi
- [ ] Graceful handling saat Redis unavailable
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
