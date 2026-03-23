package validator

import (
	"fmt"
	"regexp"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/herdifirdausss/auth/internal/model"
)

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var validate = validator.New()

func ValidateRegisterRequest(req *model.RegisterRequest) []ValidationError {
	var errors []ValidationError

	err := validate.Struct(req)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			errors = append(errors, ValidationError{
				Field:   err.Field(),
				Message: fmt.Sprintf("Field %s failed on %s tag", err.Field(), err.Tag()),
			})
		}
	}

	// Custom validation for password complexity
	if !isValidPassword(req.Password) {
		errors = append(errors, ValidationError{
			Field:   "password",
			Message: "Password must be at least 8 characters, include uppercase, lowercase, digit, and special character",
		})
	}

	// Custom validation for username format
	if !isValidUsername(req.Username) {
		errors = append(errors, ValidationError{
			Field:   "username",
			Message: "Username must be 3-50 characters, alphanumeric + underscore only",
		})
	}

	return errors
}

func isValidPassword(s string) bool {
	var (
		hasMinLen  = len(s) >= 8
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}

func isValidUsername(s string) bool {
	re := regexp.MustCompile("^[a-zA-Z0-9_]{3,50}$")
	return re.MatchString(s)
}

func ValidatePassword(password string) error {
	if !isValidPassword(password) {
		return fmt.Errorf("weak password: must be at least 8 characters, include uppercase, lowercase, digit, and special character")
	}
	return nil
}
