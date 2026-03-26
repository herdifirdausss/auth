package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/herdifirdausss/auth/internal/service"
)

type AdminHandler struct {
	adminService service.AdminService
	logger       *slog.Logger
}

func NewAdminHandler(adminService service.AdminService, logger *slog.Logger) *AdminHandler {
	return &AdminHandler{
		adminService: adminService,
		logger:       logger,
	}
}

func (h *AdminHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.adminService.ListTenants(r.Context())
	if err != nil {
		h.logger.ErrorContext(r.Context(), "Failed to list tenants", "error", err)
		h.respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.respondJSON(w, http.StatusOK, tenants)
}

func (h *AdminHandler) UpdateTenantStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "Missing tenant ID")
		return
	}

	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.adminService.UpdateTenantStatus(r.Context(), id, req.IsActive); err != nil {
		h.logger.ErrorContext(r.Context(), "Failed to update tenant status", "error", err, "tenantID", id)
		h.respondError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Tenant status updated"})
}

func (h *AdminHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AdminHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{
		"status":  "error",
		"message": message,
	})
}
