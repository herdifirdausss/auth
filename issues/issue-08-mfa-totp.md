# Issue #08: MFA TOTP Setup, Verification & Challenge

## Labels
`feature`, `auth`, `security`, `priority:high`, `mfa`

## Branch
`feature/mfa-totp`

## Description
Implementasi Multi-Factor Authentication (MFA) menggunakan TOTP (Time-based One-Time Password). Mencakup tiga endpoint: setup, verify-setup, dan challenge.

## Prerequisites
- Issue #05 (User Login) ✅
- Issue #06 (Token Validation Middleware) ✅

## API Specification

### POST /auth/mfa/setup (authenticated)
**Request:** `{}` (empty body, user must be authenticated)
**Response (200):**
```json
{ "status": "success", "data": { "secret": "<base32>", "qr_code_url": "otpauth://totp/..." } }
```

### POST /auth/mfa/verify-setup (authenticated)
**Request:** `{ "otp_code": "123456" }`
**Response (200):**
```json
{ "status": "success", "data": { "backup_codes": ["code1","code2",...] } }
```

### POST /auth/mfa/challenge
**Request:** `{ "mfa_token": "<short JWT>", "otp_code": "123456" }`
**Response (200):** Same as login success (access_token + refresh_token cookie)

## Implementation Steps

### Step 1: TOTP & Encryption Utilities
**File:** `internal/security/totp.go`
```
- GenerateTOTPSecret() (string, error) — 32 bytes, base32
- GenerateQRCodeURL(secret, email, issuer string) string
- VerifyTOTP(secret, code string, window int) bool — allow 1 drift
```

**File:** `internal/security/encryption.go`
```
- Encrypt(plaintext, key string) (string, error) — AES-256-GCM
- Decrypt(ciphertext, key string) (string, error)
- GenerateBackupCodes(count int) ([]string, error)
- HashBackupCodes(codes []string) []string
```

### Step 2: MFA Repository
**File:** `internal/repository/mfa_repository.go` (extend)
```
- Create(ctx, method *MFAMethod) error
- FindInactiveByUser(ctx, userID, methodType string) (*MFAMethod, error)
- Activate(ctx, id string) error — SET is_active=true, is_primary=true
- SetBackupCodes(ctx, id, encrypted string) error
- FindPrimaryActive(ctx, userID string) (*MFAMethod, error)
```

### Step 3: MFA Service
**File:** `internal/service/mfa_service.go`
```
- SetupTOTP(ctx, userID, email string) (*SetupResponse, error)
- VerifySetup(ctx, userID, otpCode string) (*VerifySetupResponse, error)
- Challenge(ctx, mfaToken, otpCode string, ip, ua, fingerprint string) (*LoginResponse, error)
```

**Setup Flow:** Generate secret → encrypt → INSERT mfa_methods (inactive) → return QR + secret
**Verify-Setup Flow:** Rate limit OTP → decrypt secret → verify TOTP → activate → generate backup codes → encrypt & store
**Challenge Flow:** Verify mfa_token JWT → rate limit → decrypt + verify → create full session (reuse login step 8+)

### Step 4: Handler & Routes
**File:** `internal/handler/mfa_handler.go`
```
POST /auth/mfa/setup         → mfaHandler.Setup (auth required)
POST /auth/mfa/verify-setup  → mfaHandler.VerifySetup (auth required)
POST /auth/mfa/challenge     → mfaHandler.Challenge (no auth, uses mfa_token)
```

## Testing Requirements (100% Coverage)

### Utility Tests
```go
TestGenerateTOTPSecret_Length, TestGenerateTOTPSecret_Base32
TestVerifyTOTP_Valid, TestVerifyTOTP_Invalid, TestVerifyTOTP_WindowDrift, TestVerifyTOTP_Expired
TestEncrypt_Success, TestDecrypt_Success, TestEncrypt_Decrypt_RoundTrip
TestDecrypt_InvalidKey, TestDecrypt_CorruptedData
TestGenerateBackupCodes_Count, TestGenerateBackupCodes_Unique
```

### Service Tests
```go
TestSetupTOTP_Success, TestSetupTOTP_AlreadySetup
TestVerifySetup_Success, TestVerifySetup_InvalidCode, TestVerifySetup_RateLimited
TestVerifySetup_BackupCodesGenerated, TestVerifySetup_MethodActivated
TestChallenge_Success, TestChallenge_InvalidMFAToken, TestChallenge_ExpiredMFAToken
TestChallenge_InvalidOTP, TestChallenge_RateLimited, TestChallenge_SessionCreated
```

### Handler Tests
```go
TestSetupHandler_Success_200, TestSetupHandler_Unauthenticated_401
TestVerifySetupHandler_Success_200, TestVerifySetupHandler_InvalidCode_400
TestChallengeHandler_Success_200, TestChallengeHandler_InvalidToken_401
```

## Security Notes
- ⚠️ Secret encrypted with AES-256-GCM before DB storage
- ⚠️ Backup codes shown only once, stored as encrypted hashes
- ⚠️ Rate limit: max 5 OTP attempts per 10min per user
- ⚠️ MFA token = short-lived JWT (5 minutes)
- ⚠️ TOTP window drift = 1 (accept ±30 seconds)

## Definition of Done
- [ ] MFA setup, verify-setup, and challenge endpoints work
- [ ] TOTP verification with window drift
- [ ] AES-256-GCM encryption for secrets
- [ ] Backup codes generated and encrypted
- [ ] Rate limiting on OTP attempts
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
