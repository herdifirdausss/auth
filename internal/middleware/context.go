package middleware

import (
	"context"
	"fmt"
)

type contextKey string

const authContextKey contextKey = "auth_context"

type AuthContext struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	TenantID    string `json:"tenant_id"`
	SessionID   string `json:"session_id"`
	MFAVerified bool   `json:"mfa_verified"`
	TokenHash   string `json:"token_hash"`
}

func SetAuthContext(ctx context.Context, auth *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey, auth)
}

func GetAuthContext(ctx context.Context) (*AuthContext, error) {
	val := ctx.Value(authContextKey)
	if val == nil {
		return nil, fmt.Errorf("auth context not found in context")
	}
	auth, ok := val.(*AuthContext)
	if !ok {
		return nil, fmt.Errorf("invalid auth context type")
	}
	return auth, nil
}
