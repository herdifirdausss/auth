# Issue #10: Logout & Logout All

## Labels
`feature`, `auth`, `priority:high`, `api`

## Branch
`feature/logout`

## Description
Implementasi dua endpoint logout: single session logout dan logout-all (semua device). Termasuk session revocation, refresh token revocation, dan Redis cache cleanup.

## Prerequisites
- Issue #05 (User Login) ✅
- Issue #06 (Token Validation Middleware) ✅

## API Specification

### POST /auth/logout (authenticated)
**Response (200):** `{ "status": "success", "message": "Logged out successfully" }`

### POST /auth/logout-all (authenticated)
**Response (200):** `{ "status": "success", "message": "Logged out from all devices" }`

## Implementation Steps

### Step 1: Repository Extensions
**File:** `internal/repository/session_repository.go` (extend)
```
- RevokeByID(ctx, sessionID, reason, revokedBy string) error
- RevokeAllByUser(ctx, userID, reason string) error
```

**File:** `internal/repository/refresh_token_repository.go` (extend)
```
- RevokeBySessionID(ctx, sessionID string) error
- RevokeAllByUser(ctx, userID string) error
```

### Step 2: Service Layer
**File:** `internal/service/auth_service.go` (extend)

**Logout:**
1. Get auth context (session_id, user_id, token_hash)
2. RevokeByID(session_id, 'user_logout', user_id)
3. RevokeBySessionID(session_id) — refresh tokens
4. DEL session:cache:{token_hash} — Redis
5. Log security event 'auth.logout'

**LogoutAll:**
1. Get auth context (user_id)
2. RevokeAllByUser(user_id, 'logout_all') — sessions
3. RevokeAllByUser(user_id) — refresh tokens
4. Log security event 'auth.logout_all'

### Step 3: Handler & Routes
```
POST /auth/logout     → authHandler.Logout (auth required)
POST /auth/logout-all → authHandler.LogoutAll (auth required)
```

## Testing Requirements (100% Coverage)

### Service Tests
```go
TestLogout_Success, TestLogout_SessionRevoked, TestLogout_RefreshTokensRevoked
TestLogout_RedisCacheDeleted, TestLogout_SecurityEventLogged
TestLogoutAll_Success, TestLogoutAll_AllSessionsRevoked
TestLogoutAll_AllRefreshTokensRevoked, TestLogoutAll_SecurityEventLogged
TestLogout_DBError, TestLogoutAll_DBError
```

### Handler Tests
```go
TestLogoutHandler_Success_200, TestLogoutHandler_Unauthenticated_401
TestLogoutAllHandler_Success_200, TestLogoutAllHandler_Unauthenticated_401
TestLogoutHandler_InternalError_500
```

## Security Notes
- ⚠️ Revoke refresh tokens saat logout (prevent reuse)
- ⚠️ Clear Redis cache immediately
- ⚠️ Logout-all: Redis cache TTL=5min, akan expire sendiri

## Definition of Done
- [ ] POST /auth/logout berfungsi
- [ ] POST /auth/logout-all berfungsi
- [ ] Session + refresh tokens revoked
- [ ] Redis cache cleared (single logout)
- [ ] Security events logged
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
