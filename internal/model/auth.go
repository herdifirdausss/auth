package model

import "time"

type RegisterRequest struct {
	Username   string `json:"username" validate:"required,min=3,max=50"`
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required,min=8"`
	TenantSlug string `json:"tenant_slug" validate:"required"`
}

type RegisterResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type User struct {
	ID                string                 `json:"id"`
	Email             string                 `json:"email"`
	Username          string                 `json:"username"`
	Phone             *string                `json:"phone,omitempty"`
	IsActive          bool                   `json:"is_active"`
	IsVerified        bool                   `json:"is_verified"`
	IsSuspended       bool                   `json:"is_suspended"`
	FailedLoginCount  int                    `json:"failed_login_count"`
	LastLoginAt       *time.Time             `json:"last_login_at"`
	LastLoginIP       *string                `json:"last_login_ip"`
	PasswordChangedAt *time.Time             `json:"password_changed_at,omitempty"`
	Metadata          map[string]interface{} `json:"metadata"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	DeletedAt         *time.Time             `json:"deleted_at,omitempty"`
}

type UserCredential struct {
	UserID             string    `json:"user_id"`
	PasswordHash       string    `json:"password_hash"`
	PasswordSalt       string    `json:"password_salt"`
	PasswordAlgo       string    `json:"password_algo"`
	MustChangePassword bool      `json:"must_change_password"`
	PasswordExpiresAt  *time.Time `json:"password_expires_at,omitempty"`
	LastChangedAt      time.Time `json:"last_changed_at"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type SecurityToken struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	TokenType string                 `json:"token_type"`
	TokenHash string                 `json:"token_hash"`
	Email     *string                `json:"email,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	ExpiresAt time.Time              `json:"expires_at"`
	UsedAt    *time.Time             `json:"used_at"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	CreatedAt time.Time              `json:"created_at"`
}

type SecurityEvent struct {
	ID        string    `json:"id"`
	UserID    *string   `json:"user_id"`
	TenantID  *string   `json:"tenant_id"`
	EventType string    `json:"event_type"`
	Severity  string    `json:"severity"`
	Details   string    `json:"details"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

type Tenant struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	Settings  map[string]interface{} `json:"settings"`
	IsActive  bool                   `json:"is_active"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	DeletedAt *time.Time             `json:"deleted_at,omitempty"`
}

type TenantMembership struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	TenantID   string     `json:"tenant_id"`
	Status     string     `json:"status"`
	InvitedBy  *string    `json:"invited_by"`
	InvitedAt  time.Time  `json:"invited_at"`
	AcceptedAt *time.Time `json:"accepted_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type Session struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	TenantID          *string    `json:"tenant_id"`
	MembershipID      *string    `json:"membership_id"`
	TokenHash         string     `json:"token_hash"`
	IPAddress         string     `json:"ip_address"`
	UserAgent         string     `json:"user_agent"`
	DeviceFingerprint string     `json:"device_fingerprint"`
	DeviceName        string     `json:"device_name"`
	MFAVerified       bool       `json:"mfa_verified"`
	ExpiresAt         time.Time  `json:"expires_at"`
	IdleTimeoutAt     time.Time  `json:"idle_timeout_at"`
	LastActivityAt    time.Time  `json:"last_activity_at"`
	RevokedAt         *time.Time `json:"revoked_at"`
	RevokedReason     string     `json:"revoked_reason"`
	RevokedBy         *string    `json:"revoked_by"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type RefreshToken struct {
	ID                string     `json:"id"`
	SessionID         string     `json:"session_id"`
	UserID            string     `json:"user_id"`
	TokenHash         string     `json:"token_hash"`
	FamilyID          string     `json:"family_id"`
	Generation        int        `json:"generation"`
	ParentTokenID     *string    `json:"parent_token_id"`
	IPAddress         string     `json:"ip_address"`
	UserAgent         string     `json:"user_agent"`
	DeviceFingerprint string     `json:"device_fingerprint"`
	ExpiresAt         time.Time  `json:"expires_at"`
	UsedAt            *time.Time `json:"used_at"`
	RevokedAt         *time.Time `json:"revoked_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

type MFAMethod struct {
	ID                   string     `json:"id"`
	UserID               string     `json:"user_id"`
	MethodType           string     `json:"method_type"`
	MethodName           *string    `json:"method_name"`
	SecretEncrypted      string     `json:"secret_encrypted"`
	BackupCodesEncrypted *string    `json:"backup_codes_encrypted"`
	CredentialID         *string    `json:"credential_id,omitempty"`
	PublicKey            *string    `json:"public_key,omitempty"`
	IsActive             bool       `json:"is_active"`
	IsPrimary            bool       `json:"is_primary"`
	LastUsedAt           *time.Time `json:"last_used_at"`
	UseCount             int        `json:"use_count"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type LoginRequest struct {
	Email             string `json:"email" validate:"required,email"`
	Password          string `json:"password" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint"`
	DeviceName        string `json:"device_name"`
}

type RefreshTokenRequest struct {
	RefreshToken      string `json:"refresh_token" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	MFARequired  bool   `json:"mfa_required,omitempty"`
	MFAToken     string `json:"mfa_token,omitempty"`
}

type InviteMemberRequest struct {
	Email    string `json:"email" validate:"required,email"`
	TenantID string `json:"tenant_id" validate:"required"`
}

type AcceptInvitationRequest struct {
	TenantID string `json:"tenant_id" validate:"required"`
}

type SetupResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}

type VerifySetupRequest struct {
	OTPCode string `json:"otp_code" validate:"required"`
}

type VerifySetupResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

type ChallengeRequest struct {
	MFAToken     string `json:"mfa_token" validate:"required"`
	OTPCode      string `json:"otp_code"`
	RecoveryCode string `json:"recovery_code"`
	DeviceName   string `json:"device_name"`
	TrustDevice  bool   `json:"trust_device"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type UserPasswordHistory struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	PasswordHash string    `json:"password_hash"`
	PasswordSalt string    `json:"password_salt"`
	CreatedAt    time.Time `json:"created_at"`
}

type Role struct {
	ID          string    `json:"id"`
	TenantID    *string   `json:"tenant_id,omitempty"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	Permissions []string  `json:"permissions"`
	IsSystem     bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type TrustedDevice struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	DeviceFingerprint string     `json:"device_fingerprint"`
	DeviceName        *string    `json:"device_name"`
	DeviceType        *string    `json:"device_type"`
	TrustLevel        int        `json:"trust_level"`
	LastUsedAt        time.Time  `json:"last_used_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

type RiskAssessment struct {
	Level   RiskLevel `json:"level"`
	Reasons []string  `json:"reasons"`
	Score   int       `json:"score"`
}
