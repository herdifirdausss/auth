# Issue #07: Refresh Token Rotation (POST /auth/refresh)

## Labels
`feature`, `auth`, `priority:critical`, `api`, `security`

## Branch
`feature/refresh-token-rotation`

## Description
Implementasi refresh token rotation dengan family-based token reuse detection. Jika token reuse terdeteksi, seluruh token family dan session di-revoke.

## Prerequisites
- Issue #05 (User Login) ✅
- Issue #06 (Token Validation Middleware) ✅

## API Specification

### Request
```
POST /auth/refresh
Cookie: refresh_token=<raw_refresh>
```

### Response — Success (200)
```json
{ "status": "success", "data": { "access_token": "<JWT>", "token_type": "Bearer", "expires_in": 900 } }
```
+ `Set-Cookie: refresh_token=<new_raw>; HttpOnly; Secure; SameSite=Strict; Path=/auth; Max-Age=2592000`

### Response — Token Reuse (401)
```json
{ "status": "error", "message": "Session terminated due to suspicious activity" }
```

## Implementation Steps

### Step 1: Repository Extensions
**File:** `internal/repository/refresh_token_repository.go` (extend)
- `FindByTokenHash(ctx, tokenHash) → (*RefreshToken, error)`
- `MarkUsed(ctx, tokenID) error` — SET used_at = now()
- `RevokeByFamily(ctx, familyID) error` — revoke semua dalam family
- `Create(ctx, token) error` — INSERT dengan parent_token_id & generation+1

### Step 2: Service Layer
**File:** `internal/service/auth_service.go` (extend method RefreshToken)

**Flow:**
1. `refresh_hash = SHA256(rawRefresh)`
2. `FindByTokenHash(hash)` → jika tidak ada → 401
3. **REUSE CHECK:** jika `used_at IS NOT NULL`:
   - `RevokeByFamily(familyID)` + `RevokeSession(sessionID, 'refresh_token_reuse')`
   - Log 'auth.refresh_token_reuse' severity=CRITICAL
   - Return 401
4. `MarkUsed(currentToken.ID)`
5. Create new refresh token: same family_id, generation+1, parent=current
6. Generate new JWT access token
7. Update session activity
8. Return new tokens

### Step 3: Handler & Route
**File:** `internal/handler/auth_handler.go` (extend)
- Extract refresh_token dari cookie, call service, set new cookie
- `POST /auth/refresh → authHandler.RefreshToken`

## Testing Requirements (100% Coverage)

### Service Tests
```go
TestRefreshToken_Success
TestRefreshToken_InvalidToken
TestRefreshToken_ExpiredToken
TestRefreshToken_ReuseDetected_RevokesFamily
TestRefreshToken_ReuseDetected_RevokesSession
TestRefreshToken_ReuseDetected_LogsCritical
TestRefreshToken_GenerationIncrement
TestRefreshToken_NewTokenSameFamily
TestRefreshToken_OldTokenMarkedUsed
TestRefreshToken_DBError
```

### Handler Tests
```go
TestRefreshHandler_Success_200
TestRefreshHandler_SetNewCookie
TestRefreshHandler_NoCookie_401
TestRefreshHandler_ReuseDetected_401
TestRefreshHandler_InternalError_500
```

## Security Notes
- ⚠️ **TOKEN REUSE = KRITIS**: revoke seluruh family + session
- ⚠️ Family tracking: semua rotated tokens share `family_id`
- ⚠️ Cookie: HttpOnly, Secure, SameSite=Strict

## Definition of Done
- [ ] Token rotation berfungsi (old marked used, new created)
- [ ] Reuse detection + auto-revoke
- [ ] Critical event logged
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
