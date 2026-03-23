package router

	"net/http"
	"github.com/herdifirdausss/auth/internal/handler"
	"github.com/herdifirdausss/auth/internal/middleware"
)

func NewRouter(authHandler *handler.AuthHandler, userHandler *handler.UserHandler, authMiddleware *middleware.AuthMiddleware) *http.ServeMux {
	mux := http.NewServeMux()

	// Public Routes
	mux.HandleFunc("/auth/register", authHandler.Register)
	mux.HandleFunc("/auth/verify-email", authHandler.VerifyEmail)
	mux.HandleFunc("/auth/login", authHandler.Login)

	// Protected Routes
	mux.Handle("/auth/me", authMiddleware.Authenticate(http.HandlerFunc(userHandler.Me)))

	return mux
}
