package model

import "time"

type AuditLog struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	Action       string    `json:"action" db:"action"`
	ResourceType string    `json:"resource_type" db:"resource_type"`
	ResourceID   string    `json:"resource_id" db:"resource_id"`
	OldValues    string    `json:"old_values" db:"old_values"`
	NewValues    string    `json:"new_values" db:"new_values"`
	IPAddress    string    `json:"ip_address" db:"ip"`
	UserAgent    string    `json:"user_agent" db:"user_agent"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}
