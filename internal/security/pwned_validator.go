package security

import (
	"bufio"
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PwnedValidator checks if a password has been compromised using Have I Been Pwned API.
//go:generate mockgen -source=$GOFILE -destination=../mocks/mock_$GOFILE -package=mocks
type PwnedValidator interface {
	IsPwned(ctx context.Context, password string) (bool, int, error)
}

type DefaultPwnedValidator struct {
	httpClient *http.Client
}

func NewDefaultPwnedValidator() *DefaultPwnedValidator {
	return &DefaultPwnedValidator{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// IsPwned uses K-Anonymity to check if the password exists in breach databases.
func (v *DefaultPwnedValidator) IsPwned(ctx context.Context, password string) (bool, int, error) {
	// 1. Generate SHA-1 hash of the password
	h := sha1.New()
	h.Write([]byte(password))
	hash := fmt.Sprintf("%X", h.Sum(nil))

	prefix := hash[:5]
	suffix := hash[5:]

	// 2. Query HIBP API with the first 5 chars
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("hibp api error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("hibp api returned status %d", resp.StatusCode)
	}

	// 3. Search for the suffix in the response
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			if parts[0] == suffix {
				var count int
				fmt.Sscanf(parts[1], "%d", &count)
				return true, count, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return false, 0, err
	}

	return false, 0, nil
}
