package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error generating random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func HashToken(rawToken string) string {
	h := sha256.New()
	h.Write([]byte(rawToken))
	return hex.EncodeToString(h.Sum(nil))
}
