package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/service"
)

type WebAuthnHandler struct {
	webAuthnService service.WebAuthnService
	logger          *slog.Logger
}

func NewWebAuthnHandler(webAuthnService service.WebAuthnService, logger *slog.Logger) *WebAuthnHandler {
	return &WebAuthnHandler{
		webAuthnService: webAuthnService,
		logger:          logger,
	}
}

func (h *WebAuthnHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	options, err := h.webAuthnService.BeginRegistration(r.Context(), authCtx.UserID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "WebAuthn begin registration failed", "error", err, "userID", authCtx.UserID)
		h.respondError(w, http.StatusInternalServerError, "Failed to start registration")
		return
	}

	h.respondJSON(w, http.StatusOK, options)
}

func (h *WebAuthnHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	err = h.webAuthnService.FinishRegistration(r.Context(), authCtx.UserID, body)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "WebAuthn finish registration failed", "error", err, "userID", authCtx.UserID)
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Security key registered"})
}

func (h *WebAuthnHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	options, err := h.webAuthnService.BeginLogin(r.Context(), req.Email)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "WebAuthn begin login failed", "error", err, "email", req.Email)
		h.respondError(w, http.StatusUnauthorized, "User not found or WebAuthn not enabled")
		return
	}

	h.respondJSON(w, http.StatusOK, options)
}

func (h *WebAuthnHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string          `json:"session_id"`
		Response  json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.webAuthnService.FinishLogin(r.Context(), req.SessionID, req.Response)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "WebAuthn finish login failed", "error", err)
		h.respondError(w, http.StatusUnauthorized, "Authentication failed")
		return
	}

	h.respondJSON(w, http.StatusOK, resp)
}

func (h *WebAuthnHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *WebAuthnHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{
		"status":  "error",
		"message": message,
	})
}
