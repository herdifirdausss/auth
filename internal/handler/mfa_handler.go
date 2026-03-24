package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/service"
)

type MFAHandler struct {
	mfaService service.MFAService
}

func NewMFAHandler(mfaService service.MFAService) *MFAHandler {
	return &MFAHandler{mfaService: mfaService}
}

func (h *MFAHandler) Setup(w http.ResponseWriter, r *http.Request) {
	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		h.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	res, err := h.mfaService.SetupTOTP(r.Context(), authCtx.UserID, authCtx.Email)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
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
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, res)
}

func (h *MFAHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	var req model.ChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ip := h.getIPAddress(r)
	ua := r.UserAgent()

	res, err := h.mfaService.Challenge(r.Context(), req.MFAToken, req.OTPCode, ip, ua, "")
	if err != nil {
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
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	return strings.Split(ip, ":")[0]
}
