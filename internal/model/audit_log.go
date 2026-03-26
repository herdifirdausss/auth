package model

import "time"

type AuditLog struct {
	ID           string      `json:"id"`
	TenantID     *string     `json:"tenant_id,omitempty"`
	UserID       *string     `json:"user_id,omitempty"`
	Action       string      `json:"action"`
	ResourceType string      `json:"resource_type"`
	ResourceID   *string     `json:"resource_id,omitempty"`
	OldValues    interface{} `json:"old_values,omitempty"`
	NewValues    interface{} `json:"new_values,omitempty"`
	IPAddress    string      `json:"ip_address,omitempty"`
	UserAgent    string      `json:"user_agent,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
}
