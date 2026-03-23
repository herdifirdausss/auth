package middleware

import (
	"context"
	"fmt"
)

type contextKey string

const authContextKey contextKey = "auth_context"

type AuthContext struct {
	UserID      string
	TenantID    string
	SessionID   string
	MFAVerified bool
	TokenHash   string
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
