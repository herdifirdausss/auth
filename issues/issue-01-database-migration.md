# Issue #01: Database Migration & Schema Setup

## Labels
`infrastructure`, `database`, `priority:critical`, `migration`

## Branch
`feature/database-migration`

## Description
Jalankan dan verifikasi migration SQL untuk auth MVP. Pastikan semua 14 tabel, indexes, triggers, partitions, dan seed data ter-create dengan benar.

## Prerequisites
- PostgreSQL 15+ terinstall dan running
- Database auth sudah dibuat
- Akses superuser/owner ke database

## Acceptance Criteria
- [ ] Semua 14 tabel ter-create: `users`, `user_credentials`, `password_history`, `tenants`, `tenant_memberships`, `roles`, `membership_roles`, `sessions`, `refresh_tokens`, `security_tokens`, `mfa_methods`, `trusted_devices`, `security_events`, `audit_logs`
- [ ] Semua extensions: `uuid-ossp`, `pg_trgm`, `btree_gin`
- [ ] Semua unique indexes, covering indexes, dan partial indexes terverifikasi
- [ ] Partisi `security_events` (2026_03, 2026_04, 2026_05) ter-create
- [ ] Trigger `_set_updated_at` terpasang di semua tabel yang membutuhkan
- [ ] Seed data roles: `super_admin`, `admin`, `member`, `guest`
- [ ] Semua constraints (CHECK, FK, UNIQUE) berjalan dengan benar
- [ ] Unit test 100% coverage

## Implementation Steps

### Step 1: Buat Migration Runner
Buat file untuk menjalankan migration secara programmatic.

**File:** `internal/database/migration.go`
```
- Buat fungsi RunMigration(db *sql.DB) error
- Load file SQL dari embedded FS atau path
- Jalankan dalam transaction
- Return error jika gagal
```

### Step 2: Buat Migration File
**File:** `migrations/001_auth_mvp_schema.sql`
```
- Copy isi dari auth_mvp_migration.sql
- Pastikan idempotent (IF NOT EXISTS dimana memungkinkan)
```

### Step 3: Buat Migration Verification
**File:** `internal/database/migration_verify.go`
```
- Buat fungsi VerifyMigration(db *sql.DB) error
- Query pg_tables untuk verifikasi 14 tabel exist
- Query pg_indexes untuk verifikasi indexes exist
- Query pg_trigger untuk verifikasi triggers
- Return daftar item yang missing
```

### Step 4: Seeds Verification
```
- Query roles table
- Verifikasi 4 system roles exist dengan permissions yang benar
- super_admin: ["*"]
- admin: ["users:*","roles:*","audit:read"]
- member: ["profile:read","profile:update"]
- guest: ["profile:read"]
```

## Testing Requirements (100% Coverage)

### Unit Tests
**File:** `internal/database/migration_test.go`
```go
func TestRunMigration_Success(t *testing.T)
func TestRunMigration_AlreadyApplied(t *testing.T) // idempotent
func TestRunMigration_InvalidSQL(t *testing.T)
func TestRunMigration_ConnectionError(t *testing.T)
```

**File:** `internal/database/migration_verify_test.go`
```go
func TestVerifyMigration_AllTablesExist(t *testing.T)
func TestVerifyMigration_MissingTable(t *testing.T)
func TestVerifyMigration_AllIndexesExist(t *testing.T)
func TestVerifyMigration_AllTriggersExist(t *testing.T)
func TestVerifyMigration_SeedDataExists(t *testing.T)
func TestVerifyMigration_SeedDataPermissions(t *testing.T)
func TestVerifyMigration_PartitionsExist(t *testing.T)
func TestVerifyMigration_ConstraintsExist(t *testing.T)
```

### Integration Tests
```go
func TestMigration_FullCycle(t *testing.T)           // run + verify
func TestMigration_RollbackOnFailure(t *testing.T)   // partial failure
```

## Database Tables Reference
Lihat `auth_mvp_migration.sql` untuk definisi lengkap semua tabel.

## Security Notes
- ⚠️ Migration hanya boleh dijalankan oleh DB owner/superuser
- ⚠️ Jangan expose migration endpoint di production
- ⚠️ Backup database sebelum menjalankan migration

## Definition of Done
- [ ] Migration bisa dijalankan dari code
- [ ] Migration idempotent (safe to re-run)
- [ ] Semua 14 tabel terverifikasi
- [ ] Seed data terverifikasi
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
