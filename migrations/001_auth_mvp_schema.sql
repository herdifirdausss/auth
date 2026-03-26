-- ============================================================================
-- MVP AUTH SCHEMA v1.0 — WORLD-CLASS, NO OVERKILL
-- ============================================================================
-- Philosophy  : DB = storage only. Logic lives in app/Redis.
-- Removed     : trust_score, ip_reputation, geo/location, disposable_email,
--               webhook_events, materialized views (do in app layer)
-- Kept        : users, credentials, password history, tenants, memberships,
--               roles, sessions, refresh tokens, security tokens, MFA,
--               trusted devices, security events, audit logs
-- Partitioning: security_events only (high-volume). audit_logs = plain table.
-- ============================================================================

-- ============================================================================
-- EXTENSIONS
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- fuzzy username/email search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- composite GIN indexes

-- ============================================================================
-- 1. USERS
-- ============================================================================

CREATE TABLE users (
  id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  username             text        NOT NULL,
  email                text        NOT NULL,
  phone                text,

  -- Status flags (app reads these, never DB enforces logic)
  is_active            boolean     NOT NULL DEFAULT true,
  is_verified          boolean     NOT NULL DEFAULT false,
  is_suspended         boolean     NOT NULL DEFAULT false,

  -- Brute-force counters (incremented by app, not DB triggers)
  failed_login_count   int         NOT NULL DEFAULT 0,
  last_failed_login_at timestamptz,
  last_login_at        timestamptz,
  last_login_ip        inet,
  password_changed_at  timestamptz,

  -- Flexible key-value bag for future fields (avoid schema migrations)
  metadata             jsonb       NOT NULL DEFAULT '{}',

  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  deleted_at           timestamptz,

  CONSTRAINT users_email_format   CHECK (email    ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
  CONSTRAINT users_username_len   CHECK (char_length(username) BETWEEN 3 AND 50)
);

-- Unique active users only (soft-delete safe)
CREATE UNIQUE INDEX users_username_uidx ON users (lower(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX users_email_uidx    ON users (lower(email))    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX users_phone_uidx    ON users (phone)           WHERE deleted_at IS NULL AND phone IS NOT NULL;

-- Hot-path covering index: login lookup returns everything auth needs in one index scan
CREATE INDEX users_email_covering_idx ON users (lower(email))
  INCLUDE (id, is_active, is_verified, is_suspended)
  WHERE deleted_at IS NULL AND is_active = true;

-- Metadata search (JSONB)
CREATE INDEX users_metadata_gin_idx ON users USING gin (metadata);

-- updated_at trigger
CREATE OR REPLACE FUNCTION _set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION _set_updated_at();


-- ============================================================================
-- 2. CREDENTIALS (1-to-1 with users)
-- ============================================================================

CREATE TABLE user_credentials (
  user_id              uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

  password_hash        text        NOT NULL,
  password_algo        text        NOT NULL DEFAULT 'argon2id',
  password_salt        text        NOT NULL,

  must_change_password boolean     NOT NULL DEFAULT false,
  password_expires_at  timestamptz,

  last_changed_at      timestamptz NOT NULL DEFAULT now(),
  change_count         int         NOT NULL DEFAULT 0,

  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credentials_expires_idx ON user_credentials (password_expires_at)
  WHERE password_expires_at IS NOT NULL;

CREATE TRIGGER credentials_updated_at BEFORE UPDATE ON user_credentials
  FOR EACH ROW EXECUTE FUNCTION _set_updated_at();


-- ============================================================================
-- 3. PASSWORD HISTORY (last N passwords, checked by app)
-- ============================================================================

CREATE TABLE password_history (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash text       NOT NULL,
  password_salt text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- App queries: SELECT ... WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5
CREATE INDEX password_history_user_idx ON password_history (user_id, created_at DESC);


-- ============================================================================
-- 4. TENANTS
-- ============================================================================

CREATE TABLE tenants (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text        NOT NULL,
  slug       text        NOT NULL,
  settings   jsonb       NOT NULL DEFAULT '{}',
  is_active  boolean     NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE UNIQUE INDEX tenants_slug_uidx ON tenants (lower(slug)) WHERE deleted_at IS NULL;
CREATE INDEX        tenants_active_idx ON tenants (id)         WHERE is_active = true AND deleted_at IS NULL;

CREATE TRIGGER tenants_updated_at BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION _set_updated_at();


-- ============================================================================
-- 5. TENANT MEMBERSHIPS
-- ============================================================================

CREATE TABLE tenant_memberships (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  tenant_id   uuid        NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,

  status      text        NOT NULL DEFAULT 'invited'
                CHECK (status IN ('active', 'invited', 'suspended')),

  invited_by  uuid        REFERENCES users(id),
  invited_at  timestamptz NOT NULL DEFAULT now(),
  accepted_at timestamptz,

  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX memberships_user_tenant_uidx ON tenant_memberships (user_id, tenant_id);
CREATE INDEX        memberships_tenant_status_idx ON tenant_memberships (tenant_id, status);

-- Hot-path: permission checks (status filter keeps index tiny)
CREATE INDEX memberships_user_active_covering_idx ON tenant_memberships (user_id)
  INCLUDE (id, tenant_id, status)
  WHERE status = 'active';

CREATE TRIGGER memberships_updated_at BEFORE UPDATE ON tenant_memberships
  FOR EACH ROW EXECUTE FUNCTION _set_updated_at();


-- ============================================================================
-- 6. ROLES  (tenant-scoped + global system roles)
-- ============================================================================

CREATE TABLE roles (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid        REFERENCES tenants(id) ON DELETE CASCADE, -- NULL = global
  name        text        NOT NULL,
  description text,
  permissions jsonb       NOT NULL DEFAULT '[]',
  is_system   boolean     NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Unique name per tenant (or globally when tenant_id IS NULL)
CREATE UNIQUE INDEX roles_tenant_name_uidx ON roles (tenant_id, lower(name)) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX roles_global_name_uidx ON roles (lower(name))             WHERE tenant_id IS NULL;

-- Fast permission search: "does role have permission X?"
CREATE INDEX roles_permissions_gin_idx ON roles USING gin (permissions);

CREATE TRIGGER roles_updated_at BEFORE UPDATE ON roles
  FOR EACH ROW EXECUTE FUNCTION _set_updated_at();


-- ============================================================================
-- 7. MEMBERSHIP → ROLES  (many-to-many)
-- ============================================================================

CREATE TABLE membership_roles (
  membership_id uuid NOT NULL REFERENCES tenant_memberships(id) ON DELETE CASCADE,
  role_id       uuid NOT NULL REFERENCES roles(id)              ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (membership_id, role_id)
);

CREATE INDEX membership_roles_role_idx ON membership_roles (role_id);


-- ============================================================================
-- 8. SESSIONS
-- ============================================================================

CREATE TABLE sessions (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid        NOT NULL REFERENCES users(id)               ON DELETE CASCADE,
  tenant_id          uuid        NOT NULL REFERENCES tenants(id)             ON DELETE CASCADE,
  membership_id      uuid        NOT NULL REFERENCES tenant_memberships(id)  ON DELETE CASCADE,

  -- Store only the HASH of the bearer token (never raw token)
  token_hash         text        NOT NULL,

  -- Device binding (app validates these on each request)
  ip_address         inet        NOT NULL,
  user_agent         text,
  device_fingerprint text        NOT NULL,
  device_name        text,

  mfa_verified       boolean     NOT NULL DEFAULT false,

  last_activity_at   timestamptz NOT NULL DEFAULT now(),
  idle_timeout_at    timestamptz NOT NULL DEFAULT (now() + interval '30 minutes'),
  expires_at         timestamptz NOT NULL DEFAULT (now() + interval '7 days'),

  revoked_at         timestamptz,
  revoked_reason     text,
  revoked_by         uuid        REFERENCES users(id),

  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Token validation (most critical index in the whole schema)
CREATE UNIQUE INDEX sessions_token_hash_uidx ON sessions (token_hash)
  WHERE revoked_at IS NULL;

-- Covering index: validate token without touching heap
CREATE INDEX sessions_token_active_covering_idx ON sessions (token_hash)
  INCLUDE (id, user_id, tenant_id, mfa_verified, expires_at, idle_timeout_at)
  WHERE revoked_at IS NULL;

-- User's active session list (session management UI)
CREATE INDEX sessions_user_active_idx ON sessions (user_id, created_at DESC)
  WHERE revoked_at IS NULL;

-- Background cleanup job
CREATE INDEX sessions_cleanup_idx      ON sessions (expires_at)      WHERE revoked_at IS NULL;
CREATE INDEX sessions_idle_cleanup_idx ON sessions (idle_timeout_at) WHERE revoked_at IS NULL;


-- ============================================================================
-- 9. REFRESH TOKENS  (rotation with family tracking)
-- ============================================================================

CREATE TABLE refresh_tokens (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id         uuid        NOT NULL REFERENCES sessions(id)   ON DELETE CASCADE,
  user_id            uuid        NOT NULL REFERENCES users(id)      ON DELETE CASCADE,

  token_hash         text        NOT NULL,

  -- Family = chain of rotated tokens. Reuse of old token → revoke whole family.
  family_id          uuid        NOT NULL,
  parent_token_id    uuid        REFERENCES refresh_tokens(id) ON DELETE SET NULL,
  generation         int         NOT NULL DEFAULT 1,

  -- Security binding (app must verify these match on rotation)
  ip_address         inet        NOT NULL,
  device_fingerprint text        NOT NULL,

  expires_at         timestamptz NOT NULL DEFAULT (now() + interval '30 days'),
  used_at            timestamptz,
  revoked_at         timestamptz,

  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX refresh_tokens_hash_uidx ON refresh_tokens (token_hash);

-- Detect token reuse: find all tokens in a family
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id, created_at DESC)
  WHERE revoked_at IS NULL;

-- Background cleanup job
CREATE INDEX refresh_tokens_cleanup_idx ON refresh_tokens (expires_at)
  WHERE revoked_at IS NULL AND used_at IS NULL;


-- ============================================================================
-- 10. SECURITY TOKENS  (email verify, password reset, magic link)
-- ============================================================================

CREATE TABLE security_tokens (
  id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  token_type   text        NOT NULL
                 CHECK (token_type IN ('email_verification', 'password_reset', 'magic_link', 'email_change')),
  token_hash   text        NOT NULL,

  -- Context stored for verification (e.g., new email for email_change)
  email        text,
  ip_address   inet,
  metadata     jsonb       NOT NULL DEFAULT '{}',
  user_agent text,

  expires_at   timestamptz NOT NULL,
  used_at      timestamptz,

  created_at   timestamptz NOT NULL DEFAULT now()
);

-- Lookup by token (partial: only unused tokens)
CREATE UNIQUE INDEX security_tokens_hash_uidx ON security_tokens (token_hash)
  WHERE used_at IS NULL;

-- "Get my pending verifications"
CREATE INDEX security_tokens_user_type_idx ON security_tokens (user_id, token_type, created_at DESC);

-- Background cleanup
CREATE INDEX security_tokens_cleanup_idx ON security_tokens (expires_at)
  WHERE used_at IS NULL;


-- ============================================================================
-- 11. MFA METHODS
-- ============================================================================

CREATE TABLE mfa_methods (
  id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  method_type             text        NOT NULL
                            CHECK (method_type IN ('totp', 'sms', 'email', 'backup_codes', 'webauthn')),
  method_name             text,               -- user-friendly label

  -- Store ENCRYPTED secrets (encryption key lives in app/KMS, never in DB)
  secret_encrypted        text        NOT NULL,
  backup_codes_encrypted  text,               -- TOTP backup codes (hashed list, encrypted)

  -- WebAuthn fields (NULL for other method types)
  credential_id           text,
  public_key              text,

  is_active               boolean     NOT NULL DEFAULT true,
  is_primary              boolean     NOT NULL DEFAULT false,

  last_used_at            timestamptz,
  use_count               int         NOT NULL DEFAULT 0,

  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX mfa_user_active_idx   ON mfa_methods (user_id) WHERE is_active = true;
CREATE INDEX mfa_user_primary_idx  ON mfa_methods (user_id) WHERE is_primary = true;

CREATE TRIGGER mfa_updated_at BEFORE UPDATE ON mfa_methods
  FOR EACH ROW EXECUTE FUNCTION _set_updated_at();


-- ============================================================================
-- 12. TRUSTED DEVICES  (skip MFA on recognized devices)
-- ============================================================================

CREATE TABLE trusted_devices (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  device_fingerprint text        NOT NULL,
  device_name        text,
  device_type        text        CHECK (device_type IN ('mobile', 'desktop', 'tablet')),

  -- 1 = remember MFA for 30d, 2 = trusted corporate device, 3 = hardware-bound
  trust_level        int         NOT NULL DEFAULT 1
                       CHECK (trust_level BETWEEN 1 AND 3),

  last_used_at       timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL DEFAULT (now() + interval '90 days'),
  revoked_at         timestamptz,

  created_at         timestamptz NOT NULL DEFAULT now()
);

-- One entry per user+device (upsert on each successful MFA)
CREATE UNIQUE INDEX trusted_devices_user_fp_uidx ON trusted_devices (user_id, device_fingerprint)
  WHERE revoked_at IS NULL;

CREATE INDEX trusted_devices_cleanup_idx ON trusted_devices (expires_at)
  WHERE revoked_at IS NULL;


-- ============================================================================
-- 13. SECURITY EVENTS  (partitioned by month — high volume)
-- ============================================================================

CREATE TABLE security_events (
  id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
  user_id            uuid        REFERENCES users(id) ON DELETE SET NULL,  -- keep logs after user deletion
  tenant_id          uuid        REFERENCES tenants(id) ON DELETE SET NULL,
  session_id         uuid,                -- intentionally no FK (session may be deleted)

  event_type         text        NOT NULL,
  severity           text        NOT NULL DEFAULT 'info'
                       CHECK (severity IN ('info', 'warning', 'critical')),

  ip_address         inet,
  user_agent         text,
  device_fingerprint text,
  metadata           jsonb       NOT NULL DEFAULT '{}',
  details text DEFAULT '',

  created_at         timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- ── Partitions ─────────────────────────────────────────────────────────────
-- Add a new partition each month via a cron job or migration.
-- Template: CREATE TABLE security_events_YYYY_MM PARTITION OF security_events
--             FOR VALUES FROM ('YYYY-MM-01') TO ('YYYY-MM+1-01');

CREATE TABLE security_events_2026_03 PARTITION OF security_events
  FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE security_events_2026_04 PARTITION OF security_events
  FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE security_events_2026_05 PARTITION OF security_events
  FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

-- Indexes per partition (replicate for each new partition)
CREATE INDEX security_events_2026_03_user_idx     ON security_events_2026_03 (user_id,    created_at DESC);
CREATE INDEX security_events_2026_03_critical_idx ON security_events_2026_03 (created_at DESC) WHERE severity = 'critical';
CREATE INDEX security_events_2026_03_type_idx     ON security_events_2026_03 (event_type, created_at DESC);

CREATE INDEX security_events_2026_04_user_idx     ON security_events_2026_04 (user_id,    created_at DESC);
CREATE INDEX security_events_2026_04_critical_idx ON security_events_2026_04 (created_at DESC) WHERE severity = 'critical';
CREATE INDEX security_events_2026_04_type_idx     ON security_events_2026_04 (event_type, created_at DESC);

CREATE INDEX security_events_2026_05_user_idx     ON security_events_2026_05 (user_id,    created_at DESC);
CREATE INDEX security_events_2026_05_critical_idx ON security_events_2026_05 (created_at DESC) WHERE severity = 'critical';
CREATE INDEX security_events_2026_05_type_idx     ON security_events_2026_05 (event_type, created_at DESC);


-- ============================================================================
-- 14. AUDIT LOGS  (plain table — lower volume, easier to query for MVP)
-- ============================================================================

CREATE TABLE audit_logs (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid        REFERENCES tenants(id) ON DELETE SET NULL,
  user_id       uuid        REFERENCES users(id)   ON DELETE SET NULL,

  action        text        NOT NULL,       -- e.g. 'user.password_changed'
  resource_type text,                       -- e.g. 'user', 'role', 'session'
  resource_id   uuid,

  old_values    jsonb,
  new_values    jsonb,

  ip_address    inet,
  user_agent    text,

  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_logs_tenant_idx ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX audit_logs_user_idx   ON audit_logs (user_id,   created_at DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (action,    created_at DESC);

-- Partition audit_logs if it grows > 10M rows/month (upgrade path, not needed at MVP)


-- ============================================================================
-- SEED DATA
-- ============================================================================

INSERT INTO roles (name, permissions, is_system) VALUES
  ('super_admin', '["*"]',                                   true),
  ('admin',       '["users:*","roles:*","audit:read"]',      true),
  ('member',      '["profile:read","profile:update"]',       true),
  ('guest',       '["profile:read"]',                        true)
ON CONFLICT DO NOTHING;


-- ============================================================================
-- DATABASE CONFIGURATION NOTES  (set in postgresql.conf or via ALTER SYSTEM)
-- ============================================================================

/*
-- Recommended for a 16 GB RAM server (adjust proportionally):
ALTER SYSTEM SET max_connections             = '200';
ALTER SYSTEM SET shared_buffers             = '4GB';
ALTER SYSTEM SET effective_cache_size       = '12GB';
ALTER SYSTEM SET work_mem                   = '64MB';
ALTER SYSTEM SET maintenance_work_mem       = '512MB';
ALTER SYSTEM SET checkpoint_completion_target = '0.9';
ALTER SYSTEM SET wal_buffers               = '16MB';
ALTER SYSTEM SET random_page_cost          = '1.1';   -- SSD
ALTER SYSTEM SET default_statistics_target = '100';

-- PgBouncer (transaction pooling):
-- pool_mode            = transaction
-- max_client_conn      = 1000
-- default_pool_size    = 25
-- reserve_pool_size    = 5
*/
