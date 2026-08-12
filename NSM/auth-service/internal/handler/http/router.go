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
	// BootstrapService backs GET /v1/platform/status and
	// POST /v1/platform/bootstrap (Sprint 2.6) — the one-time
	// first-administrator setup flow.
	BootstrapService *service.BootstrapService
	// RoleService backs GET /v1/roles, GET /v1/roles/{roleId}, and
	// GET /v1/permissions (Sprint 2.7), and the user-detail endpoint's
	// role-name resolution.
	RoleService *service.RoleService
	// RBACService backs every RequirePermission gate below (Sprint 2.7) —
	// the first real authorization enforcement in this router.
	RBACService *service.RBACService
	// SecretService backs /v1/secrets* (Sprint 3 Phase 4). May be nil —
	// cmd/server/main.go only constructs one when the Secrets Engine's key
	// material is actually configured (see that file's own comment) — in
	// which case the routes below are simply never registered, rather
	// than panicking on a nil service the first time one of them runs.
	SecretService *service.SecretService
	// SecretPolicyService backs /v1/secret-policies* (Sprint 4 Task 2) —
	// path-scoped secret authorization policy administration. May be nil
	// under the same condition SecretService may be nil (see that field's
	// own comment): cmd/server/main.go only constructs one when the
	// Secrets Engine's key material is configured, since a policy with
	// nothing to authorize access to has no reason to exist.
	SecretPolicyService *service.SecretPolicyService
	TokenAuth           *util.JWTSigner
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
	users := &userHandler{svc: deps.UserService, roles: deps.RoleService, rbac: deps.RBACService}
	refresh := &refreshHandler{svc: deps.RefreshTokenService}
	logout := &logoutHandler{svc: deps.LogoutService}
	platform := &platformHandler{svc: deps.BootstrapService}
	roles := &roleHandler{svc: deps.RoleService}
	requireAuth := middleware.Auth(deps.TokenAuth)
	requireAccessToken := middleware.Authenticate(deps.AccessTokens, deps.AccessTokenAudience)
	// requirePermission composes requireAuth with a real-time,
	// database-backed authorization check (Sprint 2.7) — see
	// middleware.RequirePermission's own doc comment. Every admin route
	// below is requireAuth *and then* requirePermission, in that order:
	// authentication ("who are you") must resolve before authorization
	// ("are you allowed to do this") has an identity to check.
	requirePermission := func(permission string, h http.HandlerFunc) http.Handler {
		return requireAuth(middleware.RequirePermission(deps.RBACService, permission)(h))
	}

	mux.HandleFunc("GET /healthz", healthCheck)

	// --- platform bootstrap: unauthenticated by construction (see
	// platform_handler.go) — a caller who could authenticate wouldn't
	// need this endpoint at all ---
	mux.HandleFunc("GET /v1/platform/status", platform.status)
	mux.HandleFunc("POST /v1/platform/bootstrap", platform.bootstrap)

	// --- public: no bearer token exists yet at this point in the flow ---
	mux.HandleFunc("POST /v1/auth/login", auth.login)
	mux.HandleFunc("POST /v1/auth/token/refresh", auth.refresh) // pre-existing AuthService-backed flow, unchanged
	mux.HandleFunc("POST /v1/auth/refresh", refresh.refresh)    // Milestone 5B: RefreshTokenService-backed flow
	mux.HandleFunc("POST /v1/auth/register", users.register)    // self-service signup

	// --- protected: every route below requires a verified access token ---
	mux.Handle("POST /v1/auth/logout", requireAuth(http.HandlerFunc(auth.logout)))                  // pre-existing AuthService-backed flow, unchanged
	mux.Handle("POST /v1/auth/logout/current", requireAccessToken(http.HandlerFunc(logout.logout))) // Milestone 6B: LogoutService-backed flow

	// --- user management (Sprint 2.7): every route requires both a
	// verified access token AND the specific permission named — see
	// requirePermission above. POST /v1/users previously had no
	// authentication requirement at all; requiring users:create closes
	// that gap as a side effect of adding real authorization, not a
	// separate fix. ---
	mux.Handle("POST /v1/users", requirePermission("users:create", users.create))
	mux.Handle("GET /v1/users", requirePermission("users:read", users.list))
	// GET /v1/users/{userId} is deliberately requireAuth only, not
	// requirePermission("users:read", ...): every authenticated user must
	// still be able to view their *own* profile (the existing dashboard's
	// "Account security" card already depends on this — see
	// features/users/useCurrentUser.ts on the frontend), which is not an
	// administrative capability. get() itself checks "is this the
	// caller's own ID, or do they hold users:read" — see that handler's
	// doc comment.
	mux.Handle("GET /v1/users/{userId}", requireAuth(http.HandlerFunc(users.get)))
	mux.Handle("DELETE /v1/users/{userId}", requirePermission("users:delete", users.delete))
	mux.Handle("POST /v1/users/{userId}/disable", requirePermission("users:disable", users.disable))
	mux.Handle("POST /v1/users/{userId}/enable", requirePermission("users:disable", users.enable))
	mux.Handle("POST /v1/users/{userId}/roles", requirePermission("roles:update", users.assignRole))
	mux.Handle("DELETE /v1/users/{userId}/roles/{roleId}", requirePermission("roles:update", users.removeRole))

	// --- role/permission read API (Sprint 2.7) ---
	mux.Handle("GET /v1/roles", requirePermission("roles:read", roles.list))
	mux.Handle("GET /v1/roles/{roleId}", requirePermission("roles:read", roles.get))
	mux.Handle("GET /v1/permissions", requirePermission("roles:read", roles.listPermissions))

	// --- secrets (Sprint 3 Phase 4): every route requires both a verified
	// access token and the specific secrets:* permission named — the same
	// requirePermission composition every other admin route above already
	// uses, layered on top of SecretService's own internal RBAC check
	// (defense-in-depth, not redundant — see that service's doc comment).
	// {path...} is a Go 1.22 ServeMux trailing wildcard: it matches every
	// remaining path segment after "/v1/secrets/", slashes included, as
	// one r.PathValue("path") string — e.g. "prod/database" — never
	// resolved against a filesystem anywhere in this call chain. See
	// secretHandler.get's own doc comment for the traversal-safety
	// argument in full.
	if deps.SecretService != nil {
		secrets := &secretHandler{svc: deps.SecretService}
		mux.Handle("GET /v1/secrets", requirePermission("secrets:list", secrets.list))
		mux.Handle("POST /v1/secrets", requirePermission("secrets:create", secrets.create))
		mux.Handle("GET /v1/secrets/{path...}", requirePermission("secrets:read", secrets.get))
		mux.Handle("PUT /v1/secrets/{path...}", requirePermission("secrets:update", secrets.update))
		mux.Handle("DELETE /v1/secrets/{path...}", requirePermission("secrets:delete", secrets.delete))
	}

	// --- secret path-authorization policy administration (Sprint 4 Task
	// 2): gated on the secret_policies:* permission catalog
	// (migrations/000028), deliberately separate from secrets:* — a role
	// that can read/write secret values is not automatically a role that
	// can decide which paths other roles may reach (see
	// service.SecretPolicyService's own doc comment). SecretPolicyService
	// also performs its own internal RBAC check, the same defense-in-depth
	// double-gate secrets themselves already have — see that service's
	// authorize helper. Registered under the identical "nil means don't
	// route it" guard as /v1/secrets, since a policy service with no
	// Secrets Engine to protect has nothing to administer. ---
	if deps.SecretPolicyService != nil {
		policies := &secretPolicyHandler{svc: deps.SecretPolicyService}
		mux.Handle("POST /v1/secret-policies", requirePermission("secret_policies:create", policies.create))
		mux.Handle("GET /v1/secret-policies", requirePermission("secret_policies:read", policies.list))
		mux.Handle("GET /v1/secret-policies/{policyId}", requirePermission("secret_policies:read", policies.get))
		mux.Handle("PUT /v1/secret-policies/{policyId}", requirePermission("secret_policies:update", policies.update))
		mux.Handle("DELETE /v1/secret-policies/{policyId}", requirePermission("secret_policies:delete", policies.delete))
		mux.Handle("GET /v1/secret-policies/{policyId}/assignments", requirePermission("secret_policies:read", policies.listAssignments))
		mux.Handle("POST /v1/secret-policies/{policyId}/assignments", requirePermission("secret_policies:assign", policies.assign))
		mux.Handle("DELETE /v1/secret-policies/{policyId}/assignments/{roleId}", requirePermission("secret_policies:assign", policies.unassign))
	}

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
