package security

import (
	"strings"
)

// MatchPermission checks if the user has the required permission
func MatchPermission(userPerms []string, required string) bool {
	if len(userPerms) == 0 {
		return false
	}

	for _, p := range userPerms {
		// Exact match
		if p == required {
			return true
		}

		// Super admin wildcard
		if p == "*" {
			return true
		}

		// Resource wildcard: e.g. "users:*" matches "users:read", "users:write"
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}

	return false
}
