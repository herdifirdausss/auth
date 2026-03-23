package router

import (
	"net/http"

	"github.com/herdifirdausss/auth/internal/handler"
)

func NewRouter(authHandler *handler.AuthHandler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/register", authHandler.Register)

	return mux
}
