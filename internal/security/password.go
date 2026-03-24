package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
)

//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type PasswordHasher interface {
	Hash(password string) (hash string, salt string, err error)
	Verify(password string, hash string, salt string) (bool, error)
}

type Argon2idHasher struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func NewArgon2idHasher() *Argon2idHasher {
	return &Argon2idHasher{
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func (h *Argon2idHasher) Hash(password string) (string, string, error) {
	salt := make([]byte, h.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("error generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.Iterations, h.Memory, h.Parallelism, h.KeyLength)

	return hex.EncodeToString(hash), hex.EncodeToString(salt), nil
}

func (h *Argon2idHasher) Verify(password, hash, salt string) (bool, error) {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return false, fmt.Errorf("error decoding salt: %w", err)
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return false, fmt.Errorf("error decoding hash: %w", err)
	}

	newHash := argon2.IDKey([]byte(password), saltBytes, h.Iterations, h.Memory, h.Parallelism, h.KeyLength)

	return subtle.ConstantTimeCompare(hashBytes, newHash) == 1, nil
}
