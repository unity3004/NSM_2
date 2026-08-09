package http

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/middleware"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

type RouterDeps struct {
	AuthService *service.AuthService
	UserService *service.UserService
	// RefreshTokenService backs POST /v1/auth/refresh (Milestone 5B) — see
	// refresh_handler.go's doc comment for why it's a separate route from
	// AuthService's own POST /v1/auth/token/refresh rather than a
	// replacement for it.
	RefreshTokenService *service.RefreshTokenService
	// LogoutService backs POST /v1/auth/logout/current (Milestone 6B) —
	// see logout_handler.go's doc comment for why it's a separate route
	// from AuthService's own POST /v1/auth/logout.
	LogoutService *service.LogoutService
	TokenAuth     *util.JWTSigner
	// AccessTokens/AccessTokenAudience configure middleware.Authenticate
	// (Milestone 6A) — the first route in this router to actually require
	// it, since it's the first milestone with a concrete reason to.
	AccessTokens        *security.TokenService
	AccessTokenAudience string
	// AllowedOrigins configures middleware.CORS.
	AllowedOrigins []string
	// Logger is the base logger middleware.RequestID derives every
	// request-scoped, correlation-ID-tagged logger from — see that
	// middleware's doc comment for the propagation mechanism.
	Logger *zap.Logger
}

// NewRouter builds the complete HTTP surface for the service: global
// middleware (applied to every request, in the order that matters —
// Recover outermost so it can catch a panic in anything below it, then
// RequestID, then Logging, then CORS) wrapping a stdlib 1.22+
// http.ServeMux, with per-route method+pattern registration
// ("POST /v1/auth/login") replacing what an external router package would
// otherwise be pulled in for.
//
// Only the handful of endpoints demonstrated in this scaffold are wired
// here (auth + users) — the remaining resources in
// auth-service-openapi.yaml follow the identical
// handler → service → repository pattern; see README.md.
func NewRouter(deps RouterDeps) http.Handler {
	mux := http.NewServeMux()

	auth := &authHandler{svc: deps.AuthService}
	users := &userHandler{svc: deps.UserService}
	refresh := &refreshHandler{svc: deps.RefreshTokenService}
	logout := &logoutHandler{svc: deps.LogoutService}
	requireAuth := middleware.Auth(deps.TokenAuth)
	requireAccessToken := middleware.Authenticate(deps.AccessTokens, deps.AccessTokenAudience)

	mux.HandleFunc("GET /healthz", healthCheck)

	// --- public: no bearer token exists yet at this point in the flow ---
	mux.HandleFunc("POST /v1/auth/login", auth.login)
	mux.HandleFunc("POST /v1/auth/token/refresh", auth.refresh) // pre-existing AuthService-backed flow, unchanged
	mux.HandleFunc("POST /v1/auth/refresh", refresh.refresh)    // Milestone 5B: RefreshTokenService-backed flow
	mux.HandleFunc("POST /v1/auth/register", users.register)    // self-service signup
	mux.HandleFunc("POST /v1/users", users.create)              // admin/invite path

	// --- protected: every route below requires a verified access token ---
	mux.Handle("POST /v1/auth/logout", requireAuth(http.HandlerFunc(auth.logout)))                  // pre-existing AuthService-backed flow, unchanged
	mux.Handle("POST /v1/auth/logout/current", requireAccessToken(http.HandlerFunc(logout.logout))) // Milestone 6B: LogoutService-backed flow
	mux.Handle("GET /v1/users", requireAuth(http.HandlerFunc(users.list)))
	mux.Handle("GET /v1/users/{userId}", requireAuth(http.HandlerFunc(users.get)))
	mux.Handle("DELETE /v1/users/{userId}", requireAuth(http.HandlerFunc(users.delete)))

	var handler http.Handler = mux
	handler = middleware.CORS(deps.AllowedOrigins)(handler)
	handler = middleware.Logging(handler)
	handler = middleware.RequestID(deps.Logger)(handler)
	handler = middleware.Recover(handler)
	return handler
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
