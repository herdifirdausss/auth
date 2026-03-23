# AUTH MVP — IMPLEMENTATION GUIDE FOR AI AGENT
## World-class auth, no overkill. Every step is atomic and testable.

---

## PRINSIP KERJA
- **DB = storage only.** Semua logic (rate limiting, hashing, JWT, MFA) ada di aplikasi.
- **Redis wajib** untuk: session cache, rate limiting, CSRF token, distributed lock.
- **Setiap token yang disimpan ke DB harus di-hash** (SHA-256 atau bcrypt). Raw token hanya ada di memory/response.
- **Argon2id** untuk password. Jangan SHA/MD5/bcrypt langsung untuk password baru.

---

## STACK YANG DIASUMSIKAN
| Layer | Pilihan |
|---|---|
| DB | PostgreSQL 15+ |
| Cache | Redis 7+ |
| Runtime | Go |
| Auth token | JWT (access) + opaque token (refresh) |
| Password hash | argon2id |
| Encryption MFA secret | AES-256-GCM via app key |

---

## STEP 1 — Jalankan Migration

```bash
psql $DATABASE_URL -f auth_mvp_migration.sql
```

**Verifikasi:**
```sql
SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1;
-- Harus ada 14 tabel: users, user_credentials, password_history, tenants,
-- tenant_memberships, roles, membership_roles, sessions, refresh_tokens,
-- security_tokens, mfa_methods, trusted_devices, security_events, audit_logs
```

---

## STEP 2 — Setup Redis Keys (Naming Convention)

```
rate_limit:login:{ip}              → counter (INCR + EXPIRE 15m)
rate_limit:login_user:{user_id}    → counter (INCR + EXPIRE 15m)
rate_limit:otp:{user_id}           → counter (INCR + EXPIRE 10m)
session:cache:{token_hash}         → JSON string (SETEX 5m) ← short TTL, hot cache
csrf:{session_id}                  → token string (SETEX 1h)
lock:password_reset:{user_id}      → "1" (SET NX EX 60) ← distributed lock
```

---

## STEP 3 — Register

**Flow:**
```
POST /auth/register
  body: { username, email, password, tenant_slug? }

1. Validate email format + username length (app, not DB)
2. Check Redis blacklist if needed (app)
3. Hash password: argon2id(password, salt)
4. BEGIN transaction:
   a. INSERT INTO users → get user_id
   b. INSERT INTO user_credentials (user_id, password_hash, password_salt, password_algo)
   c. If tenant_slug provided:
      - SELECT id FROM tenants WHERE lower(slug) = lower(tenant_slug)
      - INSERT INTO tenant_memberships (user_id, tenant_id, status='invited')
5. COMMIT
6. Generate email_verification token:
   a. raw_token = crypto.randomBytes(32).hex()
   b. token_hash = sha256(raw_token)
   c. INSERT INTO security_tokens (user_id, token_type='email_verification', token_hash, expires_at=now()+24h)
7. Send email with raw_token (link: /verify-email?token=<raw_token>)
8. Log: INSERT INTO security_events (user_id, event_type='user.registered', severity='info', ip_address)
9. Return 201 { message: "Check your email" }
```

---

## STEP 4 — Email Verification

```
GET /auth/verify-email?token=<raw_token>

1. token_hash = sha256(raw_token)
2. SELECT * FROM security_tokens
   WHERE token_hash = $1 AND token_type = 'email_verification'
   AND used_at IS NULL AND expires_at > now()
3. If not found → 400 "Invalid or expired token"
4. BEGIN transaction:
   a. UPDATE security_tokens SET used_at = now() WHERE id = $token.id
   b. UPDATE users SET is_verified = true WHERE id = $token.user_id
5. COMMIT
6. Log: security_events (event_type='user.email_verified')
7. Return 200 { message: "Email verified" }
```

---

## STEP 5 — Login

```
POST /auth/login
  body: { email, password, device_fingerprint, device_name? }
  headers: X-Forwarded-For (IP), User-Agent

1. Rate limit check (Redis):
   - INCR rate_limit:login:{ip}      → if > 20 dalam 15m → 429
   - INCR rate_limit:login_user:{lower(email)} → if > 10 → 429

2. Fetch user (use covering index):
   SELECT id, is_active, is_verified, is_suspended
   FROM users WHERE lower(email) = lower($email) AND deleted_at IS NULL

3. If not found → 401 (jangan beda pesan antara "email tidak ada" vs "password salah")

4. If is_suspended → 403 "Account suspended"

5. Fetch credentials:
   SELECT password_hash, password_salt, password_algo, must_change_password
   FROM user_credentials WHERE user_id = $user_id

6. Verify password: argon2id.verify(password_hash, password + salt)
   - If FAIL:
     a. UPDATE users SET failed_login_count = failed_login_count + 1,
        last_failed_login_at = now() WHERE id = $user_id
     b. If failed_login_count >= 10 → UPDATE users SET is_suspended = true
     c. Log: security_events (event_type='auth.login_failed', severity='warning')
     d. Return 401

7. If SUCCESS:
   a. Reset: UPDATE users SET failed_login_count = 0, last_login_at = now(),
      last_login_ip = $ip WHERE id = $user_id
   b. Fetch membership (jika multi-tenant, user pilih tenant dulu — skip untuk single-tenant):
      SELECT id, tenant_id FROM tenant_memberships
      WHERE user_id = $user_id AND status = 'active' LIMIT 1
   c. Check MFA:
      SELECT id, method_type FROM mfa_methods
      WHERE user_id = $user_id AND is_active = true AND is_primary = true
      → Jika ada: return 200 { mfa_required: true, mfa_token: <short-lived JWT> }
      → Jika tidak ada: lanjut ke step 8

8. Create session:
   a. raw_token = crypto.randomBytes(32).hex()
   b. token_hash = sha256(raw_token)
   c. INSERT INTO sessions (user_id, tenant_id, membership_id, token_hash,
      ip_address, user_agent, device_fingerprint, device_name,
      expires_at = now()+7d, idle_timeout_at = now()+30m)

9. Create refresh token:
   a. raw_refresh = crypto.randomBytes(32).hex()
   b. refresh_hash = sha256(raw_refresh)
   c. family_id = gen_random_uuid()
   d. INSERT INTO refresh_tokens (session_id, user_id, token_hash=refresh_hash,
      family_id, generation=1, ip_address, device_fingerprint, expires_at=now()+30d)

10. Buat JWT access token:
    payload: { sub: user_id, sid: session_id, tid: tenant_id, roles: [...] }
    exp: now() + 15 minutes  ← short-lived

11. Cache session di Redis:
    SET session:cache:{token_hash} <JSON> EX 300  ← 5 menit, hotpath

12. Log: security_events (event_type='auth.login_success', severity='info')

13. Return 200:
    {
      access_token: <JWT>,       ← in body
      refresh_token: <raw>,      ← in httpOnly cookie (SameSite=Strict)
      expires_in: 900            ← seconds
    }
```

---

## STEP 6 — Token Validation Middleware

```
Setiap request ke protected endpoint:

1. Extract Bearer token dari Authorization header
2. Verify JWT signature + exp (reject langsung jika expired/invalid signature)
3. Ambil sid (session_id) dari JWT payload
4. token_hash = sha256(bearer_token)

5. Cek Redis cache dulu:
   GET session:cache:{token_hash}
   → Jika HIT: gunakan data dari cache. Done.

6. Jika MISS, query DB (covering index, no heap access):
   SELECT id, user_id, tenant_id, mfa_verified, expires_at, idle_timeout_at
   FROM sessions WHERE token_hash = $hash
   AND revoked_at IS NULL AND expires_at > now()

7. Jika tidak ada → 401

8. Cek idle timeout: jika idle_timeout_at < now() → 401, revoke session

9. Update last_activity & idle_timeout (debounce: hanya update jika > 5 menit dari update terakhir):
   UPDATE sessions SET last_activity_at = now(),
   idle_timeout_at = now() + interval '30 minutes'
   WHERE id = $session_id

10. Cache result:
    SET session:cache:{token_hash} <JSON> EX 300

11. Set request context: { user_id, tenant_id, session_id, mfa_verified }
```

---

## STEP 7 — Refresh Token Rotation

```
POST /auth/refresh
  cookie: refresh_token=<raw_refresh>

1. refresh_hash = sha256(raw_refresh)

2. SELECT * FROM refresh_tokens
   WHERE token_hash = $hash AND revoked_at IS NULL AND expires_at > now()

3. Jika tidak ada → 401

4. Jika used_at IS NOT NULL → TOKEN REUSE DETECTED:
   a. Revoke seluruh family:
      UPDATE refresh_tokens SET revoked_at = now()
      WHERE family_id = $token.family_id
   b. Revoke session:
      UPDATE sessions SET revoked_at = now(), revoked_reason = 'refresh_token_reuse'
      WHERE id = $token.session_id
   c. Log: security_events (event_type='auth.refresh_token_reuse', severity='critical')
   d. Return 401 "Session terminated due to suspicious activity"

5. Mark current token as used:
   UPDATE refresh_tokens SET used_at = now() WHERE id = $token.id

6. Create new refresh token:
   a. new_raw = crypto.randomBytes(32).hex()
   b. new_hash = sha256(new_raw)
   c. INSERT INTO refresh_tokens (session_id, user_id, token_hash=new_hash,
      family_id=$token.family_id,  ← same family
      parent_token_id=$token.id,
      generation=$token.generation + 1,
      ip_address, device_fingerprint,
      expires_at=now()+30d)

7. Buat access token baru (JWT)

8. Update session activity:
   UPDATE sessions SET last_activity_at=now(), idle_timeout_at=now()+30m
   WHERE id=$token.session_id

9. Return 200 { access_token, refresh_token (cookie) }
```

---

## STEP 8 — MFA (TOTP)

```
POST /auth/mfa/setup  (authenticated)

1. Generate TOTP secret (32 bytes, base32-encoded)
2. Encrypt secret: AES-256-GCM(secret, APP_ENCRYPTION_KEY)
3. INSERT INTO mfa_methods (user_id, method_type='totp', method_name,
   secret_encrypted, is_active=false)  ← not active until verified
4. Return { qr_code_url, secret (plain, show once) }

POST /auth/mfa/verify-setup
  body: { otp_code }

1. Fetch mfa_method WHERE user_id = $uid AND method_type = 'totp' AND is_active = false
2. Decrypt secret
3. Verify TOTP code (allow 1 window drift)
4. Rate limit: INCR rate_limit:otp:{user_id} → max 5/10m
5. If valid:
   a. UPDATE mfa_methods SET is_active=true, is_primary=true
   b. Generate backup codes (10 codes, hash each, store as encrypted JSON array)
   c. UPDATE mfa_methods SET backup_codes_encrypted = $encrypted
6. Return { backup_codes: [...] }  ← show once, user must save

POST /auth/mfa/challenge
  body: { mfa_token (short JWT from login), otp_code }

1. Verify mfa_token signature + exp
2. Fetch mfa_method (primary, active)
3. Rate limit OTP
4. Decrypt + verify TOTP
5. If valid: create full session (Step 5, step 8 onwards)
```

---

## STEP 9 — Password Reset

```
POST /auth/forgot-password
  body: { email }

1. Distributed lock: SET NX lock:password_reset:{lower(email)} EX 60
   → Jika gagal (locked) → 200 quitely (anti-enumeration)
2. Fetch user by email
3. Jika tidak ada → 200 quietly (jangan reveal apakah email terdaftar)
4. raw_token = crypto.randomBytes(32).hex()
5. token_hash = sha256(raw_token)
6. INSERT INTO security_tokens (user_id, token_type='password_reset',
   token_hash, expires_at=now()+1h, ip_address)
7. Send email
8. Return 200 { message: "If the email exists, you'll receive a link" }

POST /auth/reset-password
  body: { token, new_password }

1. token_hash = sha256(token)
2. SELECT * FROM security_tokens WHERE token_hash=$hash
   AND token_type='password_reset' AND used_at IS NULL AND expires_at > now()
3. If not found → 400
4. Validate new_password (min 8 chars, complexity, app-side)
5. Check password history:
   SELECT password_hash FROM password_history
   WHERE user_id=$uid ORDER BY created_at DESC LIMIT 5
   → Verify new password against each hash. If match → 400 "Password recently used"
6. Hash new password: argon2id
7. BEGIN transaction:
   a. UPDATE user_credentials SET password_hash=$new, password_salt=$new_salt,
      last_changed_at=now(), change_count=change_count+1 WHERE user_id=$uid
   b. INSERT INTO password_history (user_id, password_hash=$new)
   c. DELETE FROM password_history WHERE user_id=$uid AND id NOT IN
      (SELECT id FROM password_history WHERE user_id=$uid ORDER BY created_at DESC LIMIT 5)
   d. UPDATE security_tokens SET used_at=now() WHERE id=$token.id
   e. Revoke all sessions except current:
      UPDATE sessions SET revoked_at=now(), revoked_reason='password_reset'
      WHERE user_id=$uid AND revoked_at IS NULL
8. COMMIT
9. Log: security_events (event_type='auth.password_reset', severity='warning')
10. Return 200
```

---

## STEP 10 — Logout

```
POST /auth/logout
  (authenticated)

1. token_hash dari current session
2. UPDATE sessions SET revoked_at=now(), revoked_reason='user_logout',
   revoked_by=$user_id WHERE id=$session_id
3. Revoke refresh tokens:
   UPDATE refresh_tokens SET revoked_at=now()
   WHERE session_id=$session_id AND revoked_at IS NULL
4. Delete Redis cache:
   DEL session:cache:{token_hash}
5. Log: security_events (event_type='auth.logout')
6. Return 200

POST /auth/logout-all  (logout dari semua device)

1. UPDATE sessions SET revoked_at=now(), revoked_reason='logout_all'
   WHERE user_id=$uid AND revoked_at IS NULL
2. UPDATE refresh_tokens SET revoked_at=now()
   WHERE user_id=$uid AND revoked_at IS NULL
3. Redis: tidak perlu delete (cache TTL = 5m, akan expire sendiri)
   Atau: scan + delete semua session:cache:{hash} milik user (opsional, jika perlu immediate)
```

---

## STEP 11 — Cron Jobs (Background Tasks)

```bash
# Jalankan setiap jam (gunakan pg_cron atau scheduler eksternal)

# 1. Hapus sessions expired
DELETE FROM sessions WHERE expires_at < now() - interval '1 day' AND revoked_at IS NOT NULL;

# 2. Hapus refresh tokens expired
DELETE FROM refresh_tokens WHERE expires_at < now() - interval '1 day';

# 3. Hapus security tokens expired
DELETE FROM security_tokens WHERE expires_at < now() - interval '1 day';

# 4. Hapus trusted devices expired
DELETE FROM trusted_devices WHERE expires_at < now() AND revoked_at IS NOT NULL;

# 5. Buat partisi bulan depan (jalankan tanggal 20-25 setiap bulan):
-- CREATE TABLE security_events_YYYY_MM PARTITION OF security_events
--   FOR VALUES FROM ('YYYY-MM-01') TO ('YYYY-MM+1-01');
-- (plus 3 indexes: user_idx, critical_idx, type_idx)

# 6. Drop partisi lama (> 12 bulan) jika tidak butuh retensi lama:
-- DROP TABLE security_events_YYYY_MM;
```

---

## STEP 12 — Permission Check Pattern

```javascript
// App layer — jangan query DB setiap request
// Ambil dari JWT payload, refresh hanya saat token di-rotate

async function hasPermission(userId, tenantId, requiredPermission) {
  // 1. Ambil dari JWT (sudah ada di request context)
  // 2. Jika perlu fresh check:
  const roles = await db.query(`
    SELECT r.permissions
    FROM membership_roles mr
    JOIN roles r ON r.id = mr.role_id
    JOIN tenant_memberships tm ON tm.id = mr.membership_id
    WHERE tm.user_id = $1 AND tm.tenant_id = $2 AND tm.status = 'active'
  `, [userId, tenantId]);

  const allPerms = roles.flatMap(r => r.permissions);
  return allPerms.includes('*') || allPerms.includes(requiredPermission);
}
```

---

## CHECKLIST KEAMANAN SEBELUM GO-LIVE

```
[ ] HTTPS only (HSTS header)
[ ] Cookie: HttpOnly, Secure, SameSite=Strict untuk refresh_token
[ ] Rate limiting di Redis untuk semua auth endpoints
[ ] argon2id dengan parameter: memory=65536, iterations=3, parallelism=4
[ ] MFA secret diencrypt sebelum masuk DB (AES-256-GCM)
[ ] JWT secret minimal 256-bit, disimpan di secret manager (bukan .env)
[ ] Semua response auth error pakai pesan generik (anti-enumeration)
[ ] CORS whitelist origin
[ ] Security headers: X-Frame-Options, X-Content-Type-Options, CSP
[ ] Audit log di semua aksi sensitif (password change, role change, dll)
[ ] Test token reuse attack (Step 7, point 4)
[ ] Test brute force lockout (Step 5, point 6b)
```

---

## UPGRADE PATH (setelah MVP)
| Fitur | Kapan tambahkan |
|---|---|
| IP reputation (block known bad IPs) | > 10k users atau ada abuse |
| Geolocation + impossible travel | > 50k users |
| Disposable email blocking | Jika spam register tinggi |
| Partition audit_logs | > 5M rows/month |
| Materialized view analytics | Butuh dashboard admin |
| Webhook events | Butuh integrasi third-party |
