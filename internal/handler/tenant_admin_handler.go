package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/herdifirdausss/auth/internal/middleware"
	"github.com/herdifirdausss/auth/internal/model"
	"github.com/herdifirdausss/auth/internal/service"
)

type TenantAdminHandler struct {
	service service.TenantAdminService
	logger  *slog.Logger
}

func NewTenantAdminHandler(s service.TenantAdminService, l *slog.Logger) *TenantAdminHandler {
	return &TenantAdminHandler{
		service: s,
		logger:  l,
	}
}

func (h *TenantAdminHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	config, err := h.service.GetTenantConfig(r.Context(), authCtx.TenantID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to get settings")
		return
	}
	h.respondJSON(w, http.StatusOK, config.Settings)
}

func (h *TenantAdminHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	var settings map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.service.UpdateTenantConfig(r.Context(), authCtx.TenantID, settings, authCtx.UserID, ip, ua); err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to update settings")
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *TenantAdminHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	roles, err := h.service.ListRoles(r.Context(), authCtx.TenantID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to list roles")
		return
	}
	h.respondJSON(w, http.StatusOK, roles)
}

func (h *TenantAdminHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	var role model.Role
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.service.CreateRole(r.Context(), authCtx.TenantID, &role, authCtx.UserID, ip, ua); err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to create role")
		return
	}
	h.respondJSON(w, http.StatusCreated, role)
}

func (h *TenantAdminHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	id := strings.TrimPrefix(r.URL.Path, "/admin/tenant/roles/")
	var role model.Role
	if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	role.ID = id

	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.service.UpdateRole(r.Context(), authCtx.TenantID, &role, authCtx.UserID, ip, ua); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondJSON(w, http.StatusOK, role)
}

func (h *TenantAdminHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	id := strings.TrimPrefix(r.URL.Path, "/admin/tenant/roles/")

	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.service.DeleteRole(r.Context(), authCtx.TenantID, id, authCtx.UserID, ip, ua); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *TenantAdminHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	members, err := h.service.ListMembers(r.Context(), authCtx.TenantID)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to list members")
		return
	}
	h.respondJSON(w, http.StatusOK, members)
}

func (h *TenantAdminHandler) UpdateMember(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	id := strings.TrimPrefix(r.URL.Path, "/admin/tenant/members/")

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.service.UpdateMemberStatus(r.Context(), authCtx.TenantID, id, req.Status, authCtx.UserID, ip, ua); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *TenantAdminHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	id := strings.TrimPrefix(r.URL.Path, "/admin/tenant/members/")

	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.service.RemoveMember(r.Context(), authCtx.TenantID, id, authCtx.UserID, ip, ua); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *TenantAdminHandler) UpdateMemberRoles(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := middleware.GetAuthContext(r.Context())
	// Expected path /admin/tenant/members/{id}/roles
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		h.respondError(w, http.StatusBadRequest, "Invalid path")
		return
	}
	id := parts[4]

	var req struct {
		RoleIDs []string `json:"role_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ip := r.RemoteAddr
	ua := r.UserAgent()
	if err := h.service.UpdateMemberRoles(r.Context(), authCtx.TenantID, id, req.RoleIDs, authCtx.UserID, ip, ua); err != nil {
		h.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *TenantAdminHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *TenantAdminHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{
		"status":  "error",
		"message": message,
	})
}
