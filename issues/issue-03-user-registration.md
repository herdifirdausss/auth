# Issue #03: User Registration (POST /auth/register)

## Labels
`feature`, `auth`, `priority:critical`, `api`

## Branch
`feature/user-registration`

## Description
Implementasi endpoint registrasi user baru dengan validasi input, hashing password (argon2id), pembuatan user + credentials dalam transaction, generate email verification token, dan logging security event.

## Prerequisites
- Issue #01 (Database Migration) ✅
- Issue #02 (Redis & Rate Limiting) ✅

## API Specification

### Request
```
POST /auth/register
Content-Type: application/json

{
  "username": "string (3-50 chars, required)",
  "email": "string (valid email, required)",
  "password": "string (min 8 chars, complexity required)",
  "tenant_slug": "string (optional)"
}
```

### Response — Success (201)
```json
{
  "status": "success",
  "message": "Registration successful. Please check your email to verify your account."
}
```

### Response — Validation Error (400)
```json
{
  "status": "error",
  "message": "Validation failed",
  "errors": [
    { "field": "email", "message": "Invalid email format" },
    { "field": "password", "message": "Password must be at least 8 characters" }
  ]
}
```

### Response — Conflict (409)
```json
{
  "status": "error",
  "message": "Username or email already exists"
}
```

## Implementation Steps

### Step 1: Request/Response Models
**File:** `internal/model/auth.go`
```
type RegisterRequest struct {
    Username   string `json:"username" validate:"required,min=3,max=50"`
    Email      string `json:"email" validate:"required,email"`
    Password   string `json:"password" validate:"required,min=8"`
    TenantSlug string `json:"tenant_slug,omitempty"`
}

type RegisterResponse struct {
    Status  string `json:"status"`
    Message string `json:"message"`
}
```

### Step 2: Input Validator
**File:** `internal/validator/auth_validator.go`
```
func ValidateRegisterRequest(req *RegisterRequest) []ValidationError
- Email: regex ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$
- Username: 3-50 characters, alphanumeric + underscore only
- Password: min 8 chars, harus ada uppercase, lowercase, digit, special char
- Sanitize input: trim whitespace, lowercase email
```

### Step 3: Password Hasher (argon2id)
**File:** `internal/security/password.go`
```
type PasswordHasher interface {
    Hash(password string) (hash string, salt string, error)
    Verify(password string, hash string, salt string) (bool, error)
}

type Argon2idHasher struct {
    Memory      uint32 // 65536 (64MB)
    Iterations  uint32 // 3
    Parallelism uint8  // 4
    SaltLength  uint32 // 16
    KeyLength   uint32 // 32
}

func NewArgon2idHasher() *Argon2idHasher
func (h *Argon2idHasher) Hash(password string) (string, string, error)
func (h *Argon2idHasher) Verify(password, hash, salt string) (bool, error)
```

### Step 4: Repository Layer
**File:** `internal/repository/user_repository.go`
```
type UserRepository interface {
    Create(ctx context.Context, tx *sql.Tx, user *model.User) error
    FindByEmail(ctx context.Context, email string) (*model.User, error)
    FindByUsername(ctx context.Context, username string) (*model.User, error)
    ExistsByEmail(ctx context.Context, email string) (bool, error)
    ExistsByUsername(ctx context.Context, username string) (bool, error)
}
```

**File:** `internal/repository/credential_repository.go`
```
type CredentialRepository interface {
    Create(ctx context.Context, tx *sql.Tx, cred *model.UserCredential) error
}
```

**File:** `internal/repository/security_token_repository.go`
```
type SecurityTokenRepository interface {
    Create(ctx context.Context, token *model.SecurityToken) error
}
```

**File:** `internal/repository/security_event_repository.go`
```
type SecurityEventRepository interface {
    Create(ctx context.Context, event *model.SecurityEvent) error
}
```

**File:** `internal/repository/tenant_repository.go`
```
type TenantRepository interface {
    FindBySlug(ctx context.Context, slug string) (*model.Tenant, error)
}
```

**File:** `internal/repository/membership_repository.go`
```
type TenantMembershipRepository interface {
    Create(ctx context.Context, tx *sql.Tx, membership *model.TenantMembership) error
}
```

### Step 5: Service Layer
**File:** `internal/service/auth_service.go`
```
type AuthService interface {
    Register(ctx context.Context, req *model.RegisterRequest, ipAddress string) (*model.RegisterResponse, error)
}

Implementasi Register:
1. Validate input (ValidateRegisterRequest)
2. Check duplicate: ExistsByEmail + ExistsByUsername
3. Hash password: argon2id
4. BEGIN transaction:
   a. INSERT users
   b. INSERT user_credentials
   c. Jika tenant_slug: FindBySlug → INSERT tenant_memberships
5. COMMIT
6. Generate verification token:
   a. raw_token = crypto.RandomBytes(32).Hex()
   b. token_hash = SHA256(raw_token)
   c. INSERT security_tokens (type='email_verification', expires=24h)
7. TODO: Send email (placeholder — kirim ke log dulu)
8. Log security event: 'user.registered'
9. Return RegisterResponse
```

### Step 6: Handler Layer
**File:** `internal/handler/auth_handler.go`
```
type AuthHandler struct {
    authService AuthService
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request)
- Parse JSON body
- Call authService.Register()
- Return response dengan status code yang sesuai
- Handle semua error cases
```

### Step 7: Route Registration
**File:** `internal/router/router.go`
```
POST /auth/register → authHandler.Register
```

## Testing Requirements (100% Coverage)

### Validator Tests
**File:** `internal/validator/auth_validator_test.go`
```go
func TestValidateRegister_ValidInput(t *testing.T)
func TestValidateRegister_EmptyUsername(t *testing.T)
func TestValidateRegister_UsernameTooShort(t *testing.T)
func TestValidateRegister_UsernameTooLong(t *testing.T)
func TestValidateRegister_InvalidUsernameChars(t *testing.T)
func TestValidateRegister_EmptyEmail(t *testing.T)
func TestValidateRegister_InvalidEmailFormat(t *testing.T)
func TestValidateRegister_EmptyPassword(t *testing.T)
func TestValidateRegister_PasswordTooShort(t *testing.T)
func TestValidateRegister_PasswordNoUppercase(t *testing.T)
func TestValidateRegister_PasswordNoLowercase(t *testing.T)
func TestValidateRegister_PasswordNoDigit(t *testing.T)
func TestValidateRegister_PasswordNoSpecialChar(t *testing.T)
func TestValidateRegister_MultipleErrors(t *testing.T)
```

### Password Hasher Tests
**File:** `internal/security/password_test.go`
```go
func TestArgon2idHasher_Hash_Success(t *testing.T)
func TestArgon2idHasher_Hash_UniqueSalt(t *testing.T)
func TestArgon2idHasher_Verify_Correct(t *testing.T)
func TestArgon2idHasher_Verify_Incorrect(t *testing.T)
func TestArgon2idHasher_Verify_EmptyPassword(t *testing.T)
func TestArgon2idHasher_Verify_CorruptedHash(t *testing.T)
func TestArgon2idHasher_Hash_DifferentResults(t *testing.T)  // same password, different hash
```

### Repository Tests (mock DB)
**File:** `internal/repository/user_repository_test.go`
```go
func TestUserRepo_Create_Success(t *testing.T)
func TestUserRepo_Create_DuplicateEmail(t *testing.T)
func TestUserRepo_Create_DuplicateUsername(t *testing.T)
func TestUserRepo_FindByEmail_Found(t *testing.T)
func TestUserRepo_FindByEmail_NotFound(t *testing.T)
func TestUserRepo_FindByEmail_CaseInsensitive(t *testing.T)
func TestUserRepo_ExistsByEmail_True(t *testing.T)
func TestUserRepo_ExistsByEmail_False(t *testing.T)
func TestUserRepo_ExistsByUsername_True(t *testing.T)
func TestUserRepo_ExistsByUsername_False(t *testing.T)
```

### Service Tests (mock repo)
**File:** `internal/service/auth_service_test.go`
```go
func TestRegister_Success(t *testing.T)
func TestRegister_DuplicateEmail(t *testing.T)
func TestRegister_DuplicateUsername(t *testing.T)
func TestRegister_InvalidInput(t *testing.T)
func TestRegister_WithTenantSlug_Success(t *testing.T)
func TestRegister_WithTenantSlug_NotFound(t *testing.T)
func TestRegister_DBError_Rollback(t *testing.T)
func TestRegister_TokenGeneration(t *testing.T)
func TestRegister_SecurityEventLogged(t *testing.T)
```

### Handler Tests (mock service)
**File:** `internal/handler/auth_handler_test.go`
```go
func TestRegisterHandler_Success_201(t *testing.T)
func TestRegisterHandler_InvalidJSON_400(t *testing.T)
func TestRegisterHandler_ValidationError_400(t *testing.T)
func TestRegisterHandler_DuplicateEmail_409(t *testing.T)
func TestRegisterHandler_InternalError_500(t *testing.T)
func TestRegisterHandler_MethodNotAllowed_405(t *testing.T)
```

## Security Notes
- ⚠️ Argon2id params: memory=65536, iterations=3, parallelism=4
- ⚠️ Jangan return detail error "email sudah terdaftar" di response publik (anti-enumeration) — gunakan 409 generic
- ⚠️ Raw token hanya di memory/response, yang disimpan ke DB = SHA-256 hash
- ⚠️ Transaction wajib: user + credentials harus atomic
- ⚠️ Trim & lowercase email sebelum check duplicate dan insert

## Definition of Done
- [ ] Endpoint POST /auth/register berfungsi
- [ ] Validasi input lengkap (email, username, password complexity)
- [ ] Password di-hash dengan argon2id
- [ ] Data user + credentials di-insert dalam transaction
- [ ] Email verification token ter-generate dan tersimpan (hash)
- [ ] Security event ter-log
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
