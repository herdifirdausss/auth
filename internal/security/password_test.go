package security

import (
	"testing"
)

func TestArgon2idHasher(t *testing.T) {
	h := NewArgon2idHasher()
	password := "Secret123!"

	hash, salt, err := h.Hash(password)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}

	if hash == "" || salt == "" {
		t.Fatal("expected hash and salt to be non-empty")
	}

	verified, err := h.Verify(password, hash, salt)
	if err != nil {
		t.Fatalf("unexpected error verifying password: %v", err)
	}
	if !verified {
		t.Error("expected password to be verified")
	}

	verified, err = h.Verify("wrong_password", hash, salt)
	if err != nil {
		t.Fatalf("unexpected error verifying wrong password: %v", err)
	}
	if verified {
		t.Error("expected wrong password verification to fail")
	}
}
