package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchPermission(t *testing.T) {
	tests := []struct {
		name      string
		userPerms []string
		required  string
		expected  bool
	}{
		{
			name:      "ExactMatch",
			userPerms: []string{"users:read", "users:write"},
			required:  "users:read",
			expected:  true,
		},
		{
			name:      "NoMatch",
			userPerms: []string{"users:read"},
			required:  "users:write",
			expected:  false,
		},
		{
			name:      "SuperAdminWildcard",
			userPerms: []string{"*"},
			required:  "users:delete",
			expected:  true,
		},
		{
			name:      "ResourceWildcard",
			userPerms: []string{"users:*", "roles:read"},
			required:  "users:write",
			expected:  true,
		},
		{
			name:      "ResourceWildcard_NoMatch",
			userPerms: []string{"users:*"},
			required:  "roles:write",
			expected:  false,
		},
		{
			name:      "EmptyPermissions",
			userPerms: []string{},
			required:  "users:read",
			expected:  false,
		},
		{
			name:      "MultipleRoles",
			userPerms: []string{"users:read", "roles:read", "billing:*"},
			required:  "billing:invoice:create",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchPermission(tt.userPerms, tt.required)
			assert.Equal(t, tt.expected, result)
		})
	}
}
