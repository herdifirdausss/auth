# Issue #12: Permission Check System (RBAC)

## Labels
`feature`, `auth`, `security`, `priority:high`, `rbac`

## Branch
`feature/permission-check`

## Description
Implementasi Role-Based Access Control (RBAC) dengan permission check utility. Permissions diambil dari JWT payload pada setiap request, fresh check ke DB hanya saat token rotation.

## Prerequisites
- Issue #05 (User Login) ✅
- Issue #06 (Token Validation Middleware) ✅

## Permission Structure
- Roles per tenant, stored in `membership_roles` join table
- Permissions stored as JSONB array in `roles.permissions`
- Format: `resource:action` (e.g., `users:read`, `roles:*`, `profile:update`)
- Wildcard: `*` = super admin, `resource:*` = all actions on resource

## Implementation Steps

### Step 1: Permission Service
**File:** `internal/service/permission_service.go`
```
type PermissionService interface {
    HasPermission(ctx context.Context, userID, tenantID, permission string) (bool, error)
    GetUserPermissions(ctx context.Context, userID, tenantID string) ([]string, error)
    GetUserRoles(ctx context.Context, userID, tenantID string) ([]model.Role, error)
}
```

**Logic:**
1. Query: membership_roles → roles → get permissions JSONB
2. Flatten all permissions from all roles
3. Check: `allPerms.includes('*') || allPerms.includes(requiredPermission)` or resource wildcard

### Step 2: Permission Repository
**File:** `internal/repository/role_repository.go`
```
type RoleRepository interface {
    FindPermissionsByUserAndTenant(ctx context.Context, userID, tenantID string) ([]string, error)
    FindRolesByMembership(ctx context.Context, membershipID string) ([]model.Role, error)
}
```

### Step 3: Permission Middleware
**File:** `internal/middleware/permission_middleware.go`
```
func RequirePermission(permService PermissionService, permission string) func(http.Handler) http.Handler
- Get auth context
- Call HasPermission
- If denied → 403 Forbidden
```

### Step 4: Permission Matcher Utility
**File:** `internal/security/permission.go`
```
func MatchPermission(userPerms []string, required string) bool
- Check exact match
- Check wildcard "*"
- Check resource wildcard "resource:*" for "resource:action"
```

## Testing Requirements (100% Coverage)

### Permission Matcher Tests
```go
TestMatchPermission_ExactMatch, TestMatchPermission_NoMatch
TestMatchPermission_SuperAdminWildcard
TestMatchPermission_ResourceWildcard
TestMatchPermission_EmptyPermissions
TestMatchPermission_MultipleRoles
```

### Service Tests
```go
TestHasPermission_Allowed, TestHasPermission_Denied
TestHasPermission_SuperAdmin, TestHasPermission_ResourceWildcard
TestGetUserPermissions_Success, TestGetUserPermissions_NoRoles
TestGetUserRoles_Success
```

### Middleware Tests
```go
TestPermissionMiddleware_Allowed, TestPermissionMiddleware_Denied_403
TestPermissionMiddleware_NoAuthContext_401
TestPermissionMiddleware_ServiceError_500
```

## Definition of Done
- [ ] Permission check utility works
- [ ] Wildcard matching (*, resource:*)
- [ ] RequirePermission middleware works
- [ ] JWT payload permissions used by default
- [ ] Unit test 100% pass
- [ ] Code ter-review dan approved
