package security

import (
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	cfg := JWTConfig{
		SecretKey:    []byte("test-secret"),
		Issuer:       "test-issuer",
		AccessExpiry: 15 * time.Minute,
	}

	claims := JWTClaims{
		Sub:   "user-123",
		Sid:   "sess-456",
		Roles: []string{"admin"},
	}

	token, err := GenerateAccessToken(cfg, claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := ValidateAccessToken(cfg, token)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

	if parsed.Sub != claims.Sub || parsed.Sid != claims.Sid {
		t.Error("claims mismatch")
	}

	// Test Expired
	cfgExp := cfg
	cfgExp.AccessExpiry = -1 * time.Minute
	expToken, _ := GenerateAccessToken(cfgExp, claims)
	_, err = ValidateAccessToken(cfg, expToken)
	if err == nil {
		t.Error("expected error for expired token")
	}

	// Test Invalid Secret
	cfgWrong := cfg
	cfgWrong.SecretKey = []byte("wrong-secret")
	_, err = ValidateAccessToken(cfgWrong, token)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestGenerateMFAToken(t *testing.T) {
	cfg := JWTConfig{
		SecretKey: []byte("test-secret"),
		Issuer:    "test-issuer",
	}

	token, err := GenerateMFAToken(cfg, "user-123", 5*time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := ValidateAccessToken(cfg, token)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}

	if parsed.Sub != "user-123" {
		t.Error("sub mismatch")
	}
}
