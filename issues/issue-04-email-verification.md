# Issue #04: Email Verification (GET /auth/verify-email)

## Labels
`feature`, `auth`, `priority:high`, `api`

## Branch
`feature/email-verification`

## Description
Implementasi endpoint verifikasi email menggunakan token yang dikirim saat registrasi. User mengklik link dari email, server memvalidasi token dan mengupdate status `is_verified` user.

## Prerequisites
- Issue #01 (Database Migration) ✅
- Issue #03 (User Registration) ✅

## API Specification

### Request
```
GET /auth/verify-email?token=<raw_token>
```

### Response — Success (200)
```json
{
  "status": "success",
  "message": "Email verified successfully"
}
```

### Response — Invalid/Expired Token (400)
```json
{
  "status": "error",
  "message": "Invalid or expired verification token"
}
```

## Implementation Steps

### Step 1: Token Hasher Utility
**File:** `internal/security/token.go`
```
func GenerateSecureToken(length int) (string, error)
  - crypto/rand → hex encoded

func HashToken(rawToken string) string
  - SHA-256 hash → hex encoded
```

### Step 2: Repository
**File:** `internal/repository/security_token_repository.go` (extend dari Issue #03)
```
Tambahkan method:
func FindValidToken(ctx context.Context, tokenHash string, tokenType string) (*model.SecurityToken, error)
  - Query: WHERE token_hash = $1 AND token_type = $2 AND used_at IS NULL AND expires_at > now()

func MarkUsed(ctx context.Context, tx *sql.Tx, tokenID string) error
  - UPDATE security_tokens SET used_at = now() WHERE id = $1
```

**File:** `internal/repository/user_repository.go` (extend dari Issue #03)
```
Tambahkan method:
func SetVerified(ctx context.Context, tx *sql.Tx, userID string) error
  - UPDATE users SET is_verified = true WHERE id = $1
```

### Step 3: Service Layer
**File:** `internal/service/auth_service.go` (extend)
```
Tambahkan method:
func VerifyEmail(ctx context.Context, rawToken string) error

Implementasi:
1. token_hash = SHA256(rawToken)
2. FindValidToken(token_hash, 'email_verification')
3. Jika tidak ditemukan → return error "Invalid or expired token"
4. BEGIN transaction:
   a. MarkUsed(token.ID)
   b. SetVerified(token.UserID)
5. COMMIT
6. Log security event: 'user.email_verified'
```

### Step 4: Handler
**File:** `internal/handler/auth_handler.go` (extend)
```
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request)
- Extract token dari query params
- Validate token tidak empty
- Call authService.VerifyEmail()
- Return response
```

### Step 5: Route
```
GET /auth/verify-email → authHandler.VerifyEmail
```

## Testing Requirements (100% Coverage)

### Token Utility Tests
**File:** `internal/security/token_test.go`
```go
func TestGenerateSecureToken_Length(t *testing.T)
func TestGenerateSecureToken_Unique(t *testing.T)
func TestGenerateSecureToken_HexEncoded(t *testing.T)
func TestHashToken_Deterministic(t *testing.T)
func TestHashToken_DifferentInputDifferentHash(t *testing.T)
func TestHashToken_EmptyInput(t *testing.T)
```

### Repository Tests
```go
func TestSecurityTokenRepo_FindValidToken_Found(t *testing.T)
func TestSecurityTokenRepo_FindValidToken_NotFound(t *testing.T)
func TestSecurityTokenRepo_FindValidToken_Expired(t *testing.T)
func TestSecurityTokenRepo_FindValidToken_AlreadyUsed(t *testing.T)
func TestSecurityTokenRepo_FindValidToken_WrongType(t *testing.T)
func TestSecurityTokenRepo_MarkUsed_Success(t *testing.T)
func TestUserRepo_SetVerified_Success(t *testing.T)
```

### Service Tests
```go
func TestVerifyEmail_Success(t *testing.T)
func TestVerifyEmail_InvalidToken(t *testing.T)
func TestVerifyEmail_ExpiredToken(t *testing.T)
func TestVerifyEmail_AlreadyUsed(t *testing.T)
func TestVerifyEmail_EmptyToken(t *testing.T)
func TestVerifyEmail_DBError_Rollback(t *testing.T)
func TestVerifyEmail_SecurityEventLogged(t *testing.T)
```

### Handler Tests
```go
func TestVerifyEmailHandler_Success_200(t *testing.T)
func TestVerifyEmailHandler_MissingToken_400(t *testing.T)
func TestVerifyEmailHandler_InvalidToken_400(t *testing.T)
func TestVerifyEmailHandler_InternalError_500(t *testing.T)
```

## Security Notes
- ⚠️ Token hanya valid 24 jam
- ⚠️ Token single-use (tandai `used_at` saat dipakai)
- ⚠️ Gunakan SHA-256 untuk perbandingan, bukan raw token lookup
- ⚠️ Pesan error generic: "Invalid or expired token" (jangan bedakan tidak ada vs expired)
- ⚠️ Transaction: mark used + set verified harus atomic

## Definition of Done
- [ ] Endpoint GET /auth/verify-email berfungsi
- [ ] Token di-hash sebelum lookup ke DB
- [ ] Token expired/used ditolak
- [ ] User is_verified diupdate dalam transaction
- [ ] Security event ter-log
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
