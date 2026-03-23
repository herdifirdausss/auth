# Issue #13: Security Headers & Hardening Middleware

## Labels
`feature`, `security`, `priority:critical`, `middleware`

## Branch
`feature/security-headers`

## Description
Implementasi security headers middleware dan audit logging untuk memenuhi checklist keamanan sebelum go-live. Termasuk HTTPS enforcement, CORS, CSRF protection, dan security headers standar.

## Prerequisites
- Issue #02 (Redis — CSRF) ✅
- Issue #06 (Token Validation Middleware) ✅

## Checklist Keamanan
```
[x] HTTPS only (HSTS header)
[x] Cookie: HttpOnly, Secure, SameSite=Strict
[x] Rate limiting (Issue #02)
[x] argon2id (Issue #03)
[x] MFA secret encrypted AES-256-GCM (Issue #08)
[x] JWT secret from secret manager
[x] Generic error messages (anti-enumeration)
[ ] CORS whitelist origin           ← this issue
[ ] Security headers                ← this issue
[ ] CSRF protection                 ← this issue
[ ] Audit logging middleware        ← this issue
```

## Implementation Steps

### Step 1: Security Headers Middleware
**File:** `internal/middleware/security_headers.go`
```
func SecurityHeaders(next http.Handler) http.Handler

Headers to set:
- Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 0  (modern browsers, CSP preferred)
- Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: camera=(), microphone=(), geolocation=()
- Cache-Control: no-store (for auth endpoints)
```

### Step 2: CORS Middleware
**File:** `internal/middleware/cors.go`
```
type CORSConfig struct {
    AllowedOrigins   []string
    AllowedMethods   []string
    AllowedHeaders   []string
    AllowCredentials bool
    MaxAge           int
}

func CORS(config CORSConfig) func(http.Handler) http.Handler
- Validate Origin against whitelist
- Handle preflight OPTIONS
- Set Access-Control-* headers
```

### Step 3: CSRF Middleware
**File:** `internal/middleware/csrf.go`
```
func CSRFProtection(csrfManager *redis.CSRFManager) func(http.Handler) http.Handler
- Skip for GET, HEAD, OPTIONS
- For state-changing requests (POST, PUT, DELETE):
  - Extract CSRF token from header (X-CSRF-Token)
  - Validate against Redis store
  - Reject if invalid → 403
```

### Step 4: Audit Log Middleware
**File:** `internal/middleware/audit_log.go`
```
func AuditLog(auditRepo repository.AuditLogRepository) func(http.Handler) http.Handler
- Log semua aksi sensitif (POST/PUT/DELETE ke auth/admin endpoints)
- Record: user_id, action, resource_type, resource_id, ip, user_agent, old/new values
```

**File:** `internal/repository/audit_log_repository.go`
```
type AuditLogRepository interface {
    Create(ctx context.Context, log *model.AuditLog) error
}
```

### Step 5: Request ID Middleware
**File:** `internal/middleware/request_id.go`
```
func RequestID(next http.Handler) http.Handler
- Generate UUID per request
- Set X-Request-ID header
- Add to context for logging
```

## Testing Requirements (100% Coverage)

### Security Headers Tests
```go
TestSecurityHeaders_AllPresent, TestSecurityHeaders_HSTSValue
TestSecurityHeaders_XFrameOptions, TestSecurityHeaders_ContentTypeOptions
TestSecurityHeaders_CSP, TestSecurityHeaders_ReferrerPolicy
TestSecurityHeaders_CacheControl
```

### CORS Tests
```go
TestCORS_AllowedOrigin, TestCORS_DisallowedOrigin
TestCORS_Preflight_Success, TestCORS_Preflight_Rejected
TestCORS_Credentials, TestCORS_MaxAge
TestCORS_Methods, TestCORS_Headers
```

### CSRF Tests
```go
TestCSRF_ValidToken, TestCSRF_InvalidToken_403
TestCSRF_MissingToken_403, TestCSRF_SkipGET
TestCSRF_SkipHEAD, TestCSRF_SkipOPTIONS
TestCSRF_RedisError
```

### Audit Log Tests
```go
TestAuditLog_PostRequest_Logged, TestAuditLog_GetRequest_Skipped
TestAuditLog_UserContext_Included, TestAuditLog_IPAddress_Captured
TestAuditLog_DBError_NoBlock
```

### Request ID Tests
```go
TestRequestID_Generated, TestRequestID_Unique
TestRequestID_InHeader, TestRequestID_InContext
```

## Definition of Done
- [ ] Security headers middleware works
- [ ] CORS whitelist berfungsi
- [ ] CSRF protection berfungsi
- [ ] Audit logging berfungsi
- [ ] Request ID tracking berfungsi
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
