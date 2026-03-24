package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/service"
)

type AuthHandler struct {
	authService service.AuthService
	logger      *slog.Logger
}

func NewAuthHandler(authService service.AuthService, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(r.Context(), "failed to decode register request", "error", err)
		h.respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ipAddress := h.getIPAddress(r)
	userAgent := r.UserAgent()

	res, err := h.authService.Register(r.Context(), &req, ipAddress, userAgent)
	if err != nil {
		if strings.Contains(err.Error(), "validation failed") {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			h.respondError(w, http.StatusConflict, err.Error())
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.respondError(w, http.StatusNotFound, err.Error())
			return
		}
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, res)
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		h.respondError(w, http.StatusBadRequest, "Token is required")
		return
	}

	ipAddress := h.getIPAddress(r)
	userAgent := r.UserAgent()

	err := h.authService.VerifyEmail(r.Context(), token, ipAddress, userAgent)
	if err != nil {
		if strings.Contains(err.Error(), "invalid or expired") {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Email verified successfully",
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(r.Context(), "failed to decode login request", "error", err)
		h.respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ipAddress := h.getIPAddress(r)
	userAgent := r.UserAgent()

	res, err := h.authService.Login(r.Context(), &req, ipAddress, userAgent)
	if err != nil {
		if strings.Contains(err.Error(), "invalid email or password") {
			h.respondError(w, http.StatusUnauthorized, err.Error())
			return
		}
		if strings.Contains(err.Error(), "too many login attempts") {
			h.respondError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		if strings.Contains(err.Error(), "suspended") {
			h.respondError(w, http.StatusForbidden, err.Error())
			return
		}
		if strings.Contains(err.Error(), "verify your email") {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if res.RefreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    res.RefreshToken,
			Path:     "/auth",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   2592000, // 30 days
		})
		res.RefreshToken = "" // Hide from JSON
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"data":   res,
	})
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("refresh_token")
	var refreshStr string
	if err == nil {
		refreshStr = cookie.Value
	} else {
		// Fallback to Authorization: Bearer <refresh_token> for tests/clients
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			// Extract everything after "bearer " and trim it
			refreshStr = strings.TrimSpace(authHeader[7:])
		}
	}

	if refreshStr == "" {
		h.respondError(w, http.StatusUnauthorized, "Refresh token required")
		return
	}

	ipAddress := h.getIPAddress(r)
	userAgent := r.UserAgent()

	res, err := h.authService.RefreshToken(r.Context(), refreshStr, ipAddress, userAgent)
	if err != nil {
		if strings.Contains(err.Error(), "suspicious activity") {
			h.logger.WarnContext(r.Context(), "suspicious refresh activity", "error", err, "ip", ipAddress)
			// Clear the suspicious cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    "",
				Path:     "/auth",
				HttpOnly: true,
				Expires:  time.Unix(0, 0),
			})
			h.respondError(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.logger.ErrorContext(r.Context(), "refresh token failed", "error", err)
		h.respondError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	if res.RefreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    res.RefreshToken,
			Path:     "/auth",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   2592000,
		})
		res.RefreshToken = ""
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"data":   res,
	})
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ipAddress := h.getIPAddress(r)
	userAgent := r.UserAgent()

	// Always return 200 for security (anti-enumeration)
	_ = h.authService.ForgotPassword(r.Context(), req.Email, ipAddress, userAgent)

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "If the email exists, you'll receive a reset link",
	})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ipAddress := h.getIPAddress(r)
	userAgent := r.UserAgent()

	err := h.authService.ResetPassword(r.Context(), req.Token, req.NewPassword, ipAddress, userAgent)
	if err != nil {
		if strings.Contains(err.Error(), "invalid or expired") ||
			strings.Contains(err.Error(), "weak password") ||
			strings.Contains(err.Error(), "recently used") {
			h.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logger.ErrorContext(r.Context(), "password reset failed", "error", err)
		h.respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Password has been reset successfully",
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	err = h.authService.Logout(r.Context(), authCtx.SessionID, authCtx.UserID, authCtx.TokenHash)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Logout failed")
		return
	}

	// Clear refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/auth",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Logged out successfully",
	})
}

func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	err = h.authService.LogoutAll(r.Context(), authCtx.UserID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Logout all failed")
		return
	}

	// Clear refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/auth",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Logged out from all devices",
	})
}

func (h *AuthHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{
		"status":  "error",
		"message": message,
	})
}

func (h *AuthHandler) getIPAddress(r *http.Request) string {
	return extractIP(r.RemoteAddr)
}
