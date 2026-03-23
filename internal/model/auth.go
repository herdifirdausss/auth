package model

import "time"

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

type User struct {
	ID                string     `json:"id"`
	Email             string     `json:"email"`
	Username          string     `json:"username"`
	IsActive          bool       `json:"is_active"`
	IsVerified        bool       `json:"is_verified"`
	IsSuspended       bool       `json:"is_suspended"`
	FailedLoginCount int        `json:"failed_login_count"`
	LastLoginAt       *time.Time `json:"last_login_at"`
	LastLoginIP       string     `json:"last_login_ip"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type UserCredential struct {
	ID                    string    `json:"id"`
	UserID                string    `json:"user_id"`
	PasswordHash          string    `json:"password_hash"`
	PasswordSalt          string    `json:"password_salt"`
	PasswordAlgo          string    `json:"password_algo"`
	MustChangePassword    bool      `json:"must_change_password"`
	LastChangedAt         time.Time `json:"last_changed_at"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

type SecurityToken struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	TokenType   string     `json:"token_type"`
	TokenHash   string     `json:"token_hash"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at"`
	IPAddress   string     `json:"ip_address"`
	UserAgent   string     `json:"user_agent"`
	CreatedAt   time.Time  `json:"created_at"`
}

type SecurityEvent struct {
	ID            string    `json:"id"`
	UserID        *string   `json:"user_id"`
	TenantID      *string   `json:"tenant_id"`
	EventType     string    `json:"event_type"`
	Severity      string    `json:"severity"`
	Details       string    `json:"details"`
	IPAddress     string    `json:"ip_address"`
	UserAgent     string    `json:"user_agent"`
	CreatedAt     time.Time `json:"created_at"`
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type TenantMembership struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
