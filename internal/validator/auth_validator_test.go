package validator

import (
	"testing"

	"github.com/herdifirdausss/auth/internal/model"
)

func TestValidateRegisterRequest(t *testing.T) {
	tests := []struct {
		name     string
		req      *model.RegisterRequest
		wantErr  bool
		errCount int
	}{
		{
			name: "Valid Input",
			req: &model.RegisterRequest{
				Username: "test_user",
				Email:    "test@example.com",
				Password:   "Password123!",
				TenantSlug: "test-tenant",
			},
			wantErr:  false,
			errCount: 0,
		},
		{
			name: "Invalid Email",
			req: &model.RegisterRequest{
				Username: "test_user",
				Email:    "invalid-email",
				Password:   "Password123!",
				TenantSlug: "test-tenant",
			},
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "Too Short Username",
			req: &model.RegisterRequest{
				Username: "te",
				Email:    "test@example.com",
				Password:   "Password123!",
				TenantSlug: "test-tenant",
			},
			wantErr:  true,
			errCount: 2,
		},
		{
			name: "Weak Password",
			req: &model.RegisterRequest{
				Username: "test_user",
				Email:    "test@example.com",
				Password:   "password",
				TenantSlug: "test-tenant",
			},
			wantErr:  true,
			errCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateRegisterRequest(tt.req)
			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("ValidateRegisterRequest() error = %v, wantErr %v", errs, tt.wantErr)
			}
			if len(errs) != tt.errCount {
				t.Errorf("ValidateRegisterRequest() error count = %d, want %d", len(errs), tt.errCount)
			}
		})
	}
}
