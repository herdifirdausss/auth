package middleware

import (
	"context"
	"testing"
)

func TestAuthContext(t *testing.T) {
	ctx := context.Background()
	auth := &AuthContext{
		UserID: "user-123",
	}

	ctx = SetAuthContext(ctx, auth)
	got, err := GetAuthContext(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != "user-123" {
		t.Errorf("expected user-123, got %s", got.UserID)
	}

	_, err = GetAuthContext(context.Background())
	if err == nil {
		t.Error("expected error for missing context")
	}
}
