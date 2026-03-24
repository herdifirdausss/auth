package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{"Valid", "Bearer test-token", "test-token", false},
		{"Missing", "", "", true},
		{"Wrong Scheme", "Basic abc", "", true},
		{"Malformed", "Bearer", "", true},
		{"Empty Token", "Bearer ", "", true}, // parts[1] will be ""
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			got, err := extractBearerToken(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("extractBearerToken() got = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestShouldUpdateActivity(t *testing.T) {
	if shouldUpdateActivity(time.Now().Add(-4 * time.Minute)) {
		t.Error("expected false for 4 min ago")
	}
	if !shouldUpdateActivity(time.Now().Add(-6 * time.Minute)) {
		t.Error("expected true for 6 min ago")
	}
}

func TestWriteUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	writeUnauthorized(w, "test message")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected application/json")
	}
}
