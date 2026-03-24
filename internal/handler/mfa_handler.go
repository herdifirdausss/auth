package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/service"
)

type MFAHandler struct {
	mfaService service.MFAService
	logger      *slog.Logger
}

func NewMFAHandler(mfaService service.MFAService, logger *slog.Logger) *MFAHandler {
	return &MFAHandler{
		mfaService: mfaService,
		logger:      logger,
	}
}

func (h *MFAHandler) Setup(w http.ResponseWriter, r *http.Request) {
	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	res, err := h.mfaService.SetupTOTP(r.Context(), authCtx.UserID, authCtx.Email)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "MFA setup failed", "error", err, "userID", authCtx.UserID)
		h.respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.respondJSON(w, http.StatusOK, res)
}

func (h *MFAHandler) VerifySetup(w http.ResponseWriter, r *http.Request) {
	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req model.VerifySetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	res, err := h.mfaService.VerifySetup(r.Context(), authCtx.UserID, req.OTPCode)
	if err != nil {
		h.logger.WarnContext(r.Context(), "MFA verify setup failed", "error", err, "userID", authCtx.UserID)
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, res)
}

func (h *MFAHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	var req model.ChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.WarnContext(r.Context(), "failed to decode MFA challenge request", "error", err)
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ip := h.getIPAddress(r)
	ua := r.UserAgent()
	fingerprint := r.Header.Get("X-Device-Fingerprint")

	res, err := h.mfaService.Challenge(r.Context(), req, ip, ua, fingerprint)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "MFA challenge failed", "error", err)
		h.respondError(w, http.StatusUnauthorized, err.Error())
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

	h.respondJSON(w, http.StatusOK, res)
}

func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	if err := h.mfaService.DisableMFA(r.Context(), authCtx.UserID); err != nil {
		h.logger.ErrorContext(r.Context(), "MFA disable failed", "error", err, "userID", authCtx.UserID)
		h.respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "MFA disabled"})
}

func (h *MFAHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *MFAHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{
		"status":  "error",
		"message": message,
	})
}

func (h *MFAHandler) getIPAddress(r *http.Request) string {
	return extractIP(r.RemoteAddr)
}
