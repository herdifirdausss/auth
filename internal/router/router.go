package router

	"net/http"
	"github.com/herdifirdausss/auth/internal/handler"
	"github.com/herdifirdausss/auth/internal/middleware"
)

func NewRouter(authHandler *handler.AuthHandler, userHandler *handler.UserHandler, mfaHandler *handler.MFAHandler, authMiddleware *middleware.AuthMiddleware) *http.ServeMux {
	mux := http.NewServeMux()

	// Public Routes
	mux.HandleFunc("/auth/register", authHandler.Register)
	mux.HandleFunc("/auth/verify-email", authHandler.VerifyEmail)
	mux.HandleFunc("/auth/login", authHandler.Login)
	mux.HandleFunc("/auth/token/refresh", authHandler.RefreshToken)
	mux.HandleFunc("/auth/mfa/challenge", mfaHandler.Challenge)

	// Protected Routes
	mux.Handle("/auth/me", authMiddleware.Authenticate(http.HandlerFunc(userHandler.Me)))
	mux.Handle("/auth/mfa/setup", authMiddleware.Authenticate(http.HandlerFunc(mfaHandler.Setup)))
	mux.Handle("/auth/mfa/verify-setup", authMiddleware.Authenticate(http.HandlerFunc(mfaHandler.VerifySetup)))

	return mux
}
