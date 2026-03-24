package handler

import (
	"encoding/json"
	"net/http"

	"github.com/herdifirdausss/auth/internal/middleware"
)

type UserHandler struct{}

func NewUserHandler() *UserHandler {
	return &UserHandler{}
}

func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	authCtx, err := middleware.GetAuthContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   authCtx,
	})
}
