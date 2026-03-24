package security

import (
	"testing"
)

func TestGenerateSecureToken(t *testing.T) {
	t1, err := GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(t1) != 64 { // hex encoded
		t.Errorf("expected length 64, got %d", len(t1))
	}

	t2, _ := GenerateSecureToken(32)
	if t1 == t2 {
		t.Error("expected tokens to be unique")
	}
}

func TestHashToken(t *testing.T) {
	raw := "test-token"
	h1 := HashToken(raw)
	h2 := HashToken(raw)

	if h1 != h2 {
		t.Error("expected hash to be deterministic")
	}

	h3 := HashToken("different")
	if h1 == h3 {
		t.Error("expected different tokens to have different hashes")
	}
}
