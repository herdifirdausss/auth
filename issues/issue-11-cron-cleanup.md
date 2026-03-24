# Issue #11: Background Cleanup Cron Jobs

## Labels
`feature`, `infrastructure`, `priority:medium`, `cron`

## Branch
`feature/cron-cleanup`

## Description
Implementasi background cleanup jobs untuk menghapus data expired: sessions, refresh tokens, security tokens, trusted devices. Juga termasuk auto-creation partisi security_events untuk bulan depan.

## Prerequisites
- Issue #01 (Database Migration) ✅

## Cron Schedule
Jalankan setiap jam (hourly) atau via scheduler.

## Cleanup Tasks
| # | Task | Query |
|---|------|-------|
| 1 | Hapus expired sessions | `DELETE FROM sessions WHERE expires_at < now() - interval '1 day' AND revoked_at IS NOT NULL` |
| 2 | Hapus expired refresh tokens | `DELETE FROM refresh_tokens WHERE expires_at < now() - interval '1 day'` |
| 3 | Hapus expired security tokens | `DELETE FROM security_tokens WHERE expires_at < now() - interval '1 day'` |
| 4 | Hapus expired trusted devices | `DELETE FROM trusted_devices WHERE expires_at < now() AND revoked_at IS NOT NULL` |
| 5 | Create next month partition | `CREATE TABLE security_events_YYYY_MM PARTITION OF security_events FOR VALUES FROM (...)` |
| 6 | Drop partitions > 12 months | `DROP TABLE security_events_YYYY_MM` |

## Implementation Steps

### Step 1: Cleanup Repository
**File:** `internal/repository/cleanup_repository.go`
```
type CleanupRepository interface {
    CleanupExpiredSessions(ctx context.Context) (int64, error)
    CleanupExpiredRefreshTokens(ctx context.Context) (int64, error)
    CleanupExpiredSecurityTokens(ctx context.Context) (int64, error)
    CleanupExpiredTrustedDevices(ctx context.Context) (int64, error)
    CreatePartition(ctx context.Context, year, month int) error
    DropPartition(ctx context.Context, year, month int) error
    PartitionExists(ctx context.Context, year, month int) (bool, error)
}
```

### Step 2: Cleanup Service
**File:** `internal/service/cleanup_service.go`
```
type CleanupService interface {
    RunAll(ctx context.Context) (*CleanupResult, error)
    EnsureNextMonthPartition(ctx context.Context) error
    DropOldPartitions(ctx context.Context, retentionMonths int) error
}

type CleanupResult struct {
    SessionsDeleted      int64
    RefreshTokensDeleted int64
    SecurityTokensDeleted int64
    TrustedDevicesDeleted int64
}
```

### Step 3: Cron Runner
**File:** `internal/cron/scheduler.go`
```
- Setup cron scheduler (e.g. robfig/cron)
- Register hourly cleanup job
- Register monthly partition job (tanggal 20-25)
- Graceful shutdown
```

## Testing Requirements (100% Coverage)

### Repository Tests
```go
TestCleanup_ExpiredSessions, TestCleanup_NoExpiredSessions
TestCleanup_ExpiredRefreshTokens, TestCleanup_ExpiredSecurityTokens
TestCleanup_ExpiredTrustedDevices
TestCreatePartition_Success, TestCreatePartition_AlreadyExists
TestDropPartition_Success, TestDropPartition_NotExists
TestPartitionExists_True, TestPartitionExists_False
```

### Service Tests
```go
TestRunAll_Success, TestRunAll_PartialFailure
TestEnsureNextMonthPartition_Creates, TestEnsureNextMonthPartition_AlreadyExists
TestDropOldPartitions_Success, TestDropOldPartitions_NothingToDrop
TestCleanupResult_Counts
```

## Definition of Done
- [ ] All cleanup queries work correctly
- [ ] Partition creation/deletion works
- [ ] Cron scheduler configured
- [ ] Graceful shutdown
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
