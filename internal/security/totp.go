package security

import (
	"time"

	"github.com/xlzd/gotp"
)

// GenerateTOTPSecret generates a new 32-character base32 secret.
func GenerateTOTPSecret() (string, error) {
	return gotp.RandomSecret(20), nil // 20 bytes -> 32 chars in base32
}

// GenerateQRCodeURL generates an otpauth URL for QR code generation.
func GenerateQRCodeURL(secret, email, issuer string) string {
	totp := gotp.NewDefaultTOTP(secret)
	return totp.ProvisioningUri(email, issuer)
}

// VerifyTOTP verifies a TOTP code against a secret with a window of 1 (±30s).
func VerifyTOTP(secret, code string) bool {
	return VerifyTOTPAtTime(secret, code, time.Now())
}

// VerifyTOTPAtTime verifies a TOTP code against a secret at a specific time.
func VerifyTOTPAtTime(secret, code string, t time.Time) bool {
	totp := gotp.NewDefaultTOTP(secret)
	return totp.Verify(code, t.Unix())
}
