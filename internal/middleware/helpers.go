package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

func shouldUpdateActivity(lastActivity time.Time) bool {
	return time.Since(lastActivity) > 5*time.Minute
}

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": message,
	})
}
