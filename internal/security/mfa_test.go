package security

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlzd/gotp"
)

func TestTOTP_Utilities(t *testing.T) {
	// 1. Generate Secret
	secret, err := GenerateTOTPSecret()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Len(t, secret, 32)

	// 2. Generate QR URL
	url := GenerateQRCodeURL(secret, "user@example.com", "App")
	assert.Contains(t, url, "otpauth://totp/")
	assert.Contains(t, url, "secret="+secret)

	// 3. Verify TOTP
	totp := gotp.NewDefaultTOTP(secret)
	code := totp.Now()
	assert.True(t, VerifyTOTP(secret, code))
	assert.False(t, VerifyTOTP(secret, "000000"))
}

func TestEncryption_Utilities(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")) // 32 bytes
	plaintext := "my-secret-data"

	// 1. Encrypt
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	// 2. Decrypt
	decrypted, err := Decrypt(ciphertext, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// 3. Invalid Key
	_, err = Decrypt(ciphertext, "invalid-key")
	assert.Error(t, err)
}

func TestGenerateBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes(10)
	assert.NoError(t, err)
	assert.Len(t, codes, 10)
	for _, c := range codes {
		assert.NotEmpty(t, c)
	}
}
