# Issue Cards for Authentication System (World-Class Completion)

These issue cards address the gaps in the current implementation to ensure 100% utilization of the "world-class" schema.

---

## Issue #1: Enterprise Audit Logging & Security Forensics
**Objective**: Activate `audit_logs` and complete `security_events` metadata.

### Tasks:
1.  **Repository**: Implement `PostgresAuditLogRepository` (missing implementation).
2.  **Instrumentation**:
    - Log `audit_logs` on: `role.create`, `role.update`, `user.suspended`, `tenant.settings_updated`.
    - Log `security_events` with **`session_id`**, **`device_fingerprint`**, and **`metadata`** for all auth events.
3.  **Details**: Ensure `details` field in `security_events` is never empty; provide a human-readable summary.

---

## Issue #2: WebAuthn (Passkeys) Foundation
**Objective**: Technical plumbing for modern passwordless auth.

### Tasks:
1.  **MFA Repository**: Update [mfa_repository.go](file:///Users/oyherdifirdaus/Documents/Project/auth/internal/repository/mfa_repository.go) to support `credential_id` and `public_key`.
2.  **MFA Analytics**: Update `last_used_at` and `use_count` in the database whenever an MFA method is used.
3.  **MFA Lifecycle**: Implement logic to allow `is_active=false` for MFA methods (currently always `true`).

---

## Issue #3: Session Hardening: Fingerprinting & Step-Up Auth
**Objective**: Bind sessions to devices and track MFA verification level.

### Tasks:
1.  **Device Binding**: 
    - In `AuthService`, reject refresh/access if the `device_fingerprint` changed mid-session.
    - Ensure `device_name` is always stored and returnable for "Active Sessions" UI.
2.  **MFA Verified Flag**: 
    - Initialize `mfa_verified = false` on login.
    - Update `mfa_verified = true` ONLY after successful MFA challenge.
    - Middleware should check this flag for protected routes.

---

## Issue #4: Tenant Management & Soft-Delete
**Objective**: Implement tenant settings and safe data deletion.

### Tasks:
1.  **Tenants**: Update `TenantRepository` to support `settings` (JSONB) and `is_active` status.
2.  **Soft-Delete**: 
    - Update `UserRepository` and `TenantRepository` to respect `deleted_at IS NULL`.
    - Implement `Delete` methods as soft-deletes (setting `deleted_at`).
3.  **Metadata**: Ensure `metadata` in `users` can be used for custom profile fields.

---

## Issue #5: Account Governance: Passwords & Membership
**Objective**: Enforce password policies and track membership state.

### Tasks:
1.  **Password Policy**:
    - Implement `must_change_password` logic: force password change on next login if set.
    - Implement `password_expires_at` logic.
    - Set `password_changed_at` on every successful update.
2.  **Membership**: Ensure `accepted_at` is set when an invitation is accepted.
3.  **Cleanup**: Implement a cron job or script to cleanup `trusted_devices` past their `expires_at`.
