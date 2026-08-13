package http

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/middleware"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// Rate-limit category names (Sprint 4 Task 4) — compile-time constants
// supplied at routing time, the same discipline every requirePermission
// permission string already follows, and the exact keys
// config.RateLimitConfig.API's map must use for its policies to actually
// take effect (see cmd/server/main.go's own construction). Grouped here,
// once, so a route registration and its category can never drift apart
// by typo the way two independent string literals could.
const (
	categorySecretsRead  = "secrets-read"
	categorySecretsWrite = "secrets-write"
	categoryPolicyAdmin  = "policy-admin"
	categoryUserAdmin    = "user-admin"
	categoryAuditRead    = "audit-read"
	categoryAuthRegister = "auth-register"
	categoryAuthLogout   = "auth-logout"
	// categoryServiceAccountAdmin (Sprint 5 Task 1) covers every
	// /v1/service-accounts* and /v1/api-keys* admin route — one shared
	// admin-API throttle, the same "one category per resource family"
	// convention categoryUserAdmin already establishes for /v1/users*
	// and /v1/roles*.
	categoryServiceAccountAdmin = "service-account-admin"
	// Sprint 5 Task 2: three separate categories, not one shared
	// "leases" category — see config.APIRateLimitConfig's own doc
	// comment for the reasoning (creation is the expensive/abuse-prone
	// operation, renewal is cheap bookkeeping, revocation is a safety
	// action that must stay available during an incident).
	categoryLeaseCreate = "lease-create"
	categoryLeaseRead   = "lease-read"
	categoryLeaseRenew  = "lease-renew"
	categoryLeaseRevoke = "lease-revoke"
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
	// AuditTx (Sprint 4 Task 3) is threaded into middleware.RequirePermission
	// so a 403 from *any* permission-gated route — not only the resources
	// that additionally self-check internally (SecretService, SecretPolicyService)
	// — leaves an authorization.denied audit trail. May be nil (the same
	// allowance every other AuditTxFunc dependency in this codebase makes);
	// every denial still enforces correctly without it, it just isn't audited.
	AuditTx service.AuditTxFunc
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
	// AuditService backs GET /v1/audit-logs (Sprint 4 Task 3). Unlike
	// SecretService/SecretPolicyService, this has no optional key-material
	// dependency — repository.AuditLogRepository is always available — so
	// it's nil only in a test harness that deliberately didn't wire it;
	// the nil-guard below exists for that case, not an expected production
	// deployment shape.
	AuditService *service.AuditService
	// ServiceAccountService backs /v1/service-accounts* and /v1/api-keys*
	// (Sprint 5 Task 1) — machine identity administration and
	// authentication. Unlike SecretService/SecretPolicyService, it has no
	// optional key-material dependency, so it's nil only in a test harness
	// that deliberately didn't wire it, the same AuditService precedent.
	ServiceAccountService *service.ServiceAccountService
	// LeaseService backs /v1/leases* (Sprint 5 Task 2) — dynamic-secret
	// lease issuance and lifecycle. May be nil under the same condition
	// SecretService may be nil (see that field's own comment): leases
	// reuse SecretPolicyService for path authorization, so there is
	// nothing for this to authorize against when the Secrets Engine
	// itself isn't configured.
	LeaseService *service.LeaseService
	// RateLimiter (Sprint 4 Task 4) backs every middleware.RateLimit gate
	// below — general API request throttling, distinct from AuthService/
	// RefreshTokenService's own AuthAbuseProtection (brute-force lockout,
	// unchanged by this task). Never nil in practice: cmd/server/main.go
	// wires ratelimit.NoopAPIRateLimiter when rate_limit.enabled is
	// false, the same "always a real value, never a nil check at every
	// call site" contract AuthAbuseProtection's own Noop implementation
	// already provides.
	RateLimiter ratelimit.APIRateLimiter
	TokenAuth   *util.JWTSigner
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
		return requireAuth(middleware.RequirePermission(deps.RBACService, deps.AuditTx, permission)(h))
	}
	// rateLimit (Sprint 4 Task 4) wraps an already-built handler chain in
	// the general API request throttle — applied *outside*
	// requirePermission (i.e. it runs first) so a request that will end
	// up 403'd still counts against its caller's budget, and so the
	// identity it counts against is resolved from whatever requireAuth
	// already placed on the context by the time this runs. See
	// middleware.RateLimit's own doc comment for identity resolution and
	// middleware.ratelimit.go for the category constants above.
	rateLimit := func(category string, h http.Handler) http.Handler {
		return middleware.RateLimit(deps.RateLimiter, deps.AuditTx, category)(h)
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
	// POST /v1/auth/register (Sprint 4 Task 4): rate-limited by IP alone
	// — there is no authenticated identity yet at registration time, and
	// no existing account to correlate failures against the way
	// AuthAbuseProtection's Account/Pair dimensions do for login. The
	// risk this protects against is volumetric (mass account creation),
	// not credential-guessing, so the general API throttle is the right
	// tool here rather than extending the brute-force lockout mechanism
	// to an operation that has no "wrong password" to fail against.
	mux.Handle("POST /v1/auth/register", rateLimit(categoryAuthRegister, http.HandlerFunc(users.register)))
	// POST /v1/service-accounts/{id}/token (Sprint 5 Task 1): the
	// client-credentials-style machine-auth exchange — X-Api-Key-
	// authenticated, not bearer-token-authenticated (see
	// serviceAccountHandler.token's own doc comment), so it belongs in
	// this same "no bearer token exists yet" group, never behind
	// requireAuth. Guarded by its own internal Redis-backed
	// AuthAbuseProtection check (ServiceAccountService.Authenticate,
	// ratelimit.OperationServiceAccountAuth) rather than the general
	// rateLimit(...) middleware — the identical choice auth.login already
	// makes for the same reason: this is credential-guessing risk
	// (brute-forcing a service account's secret), not request volume, and
	// AuthAbuseProtection is the mechanism built for that threat model
	// (see internal/ratelimit's own package doc comment on the
	// distinction). Registered only when ServiceAccountService is wired.
	if deps.ServiceAccountService != nil {
		accounts := &serviceAccountHandler{svc: deps.ServiceAccountService, roles: deps.RoleService, rbac: deps.RBACService}
		mux.HandleFunc("POST /v1/service-accounts/{serviceAccountId}/token", accounts.token)
	}

	// --- protected: every route below requires a verified access token ---
	// Sprint 4 Task 4: rate-limited (categoryAuthLogout) — via the general
	// API throttle, not AuthAbuseProtection's failure-counting lockout:
	// logout has no password or credential to guess, so the brute-force
	// threat model that mechanism exists for doesn't apply here (see
	// ratelimit's own package doc comment on the distinction). Both
	// routes already require a verified identity to reach at all
	// (requireAuth / requireAccessToken), so this is throttling volume
	// from an already-authenticated caller, exactly what the general
	// limiter is for.
	mux.Handle("POST /v1/auth/logout", rateLimit(categoryAuthLogout, requireAuth(http.HandlerFunc(auth.logout))))                  // pre-existing AuthService-backed flow, unchanged
	mux.Handle("POST /v1/auth/logout/current", rateLimit(categoryAuthLogout, requireAccessToken(http.HandlerFunc(logout.logout)))) // Milestone 6B: LogoutService-backed flow

	// --- user management (Sprint 2.7): every route requires both a
	// verified access token AND the specific permission named — see
	// requirePermission above. POST /v1/users previously had no
	// authentication requirement at all; requiring users:create closes
	// that gap as a side effect of adding real authorization, not a
	// separate fix. ---
	// Sprint 4 Task 4: every route in this block is additionally
	// rate-limited under categoryUserAdmin — a single shared admin-API
	// throttle for user and role management, distinct from (and more
	// generous per-request than) the read-heavy secrets categories below,
	// per the objective's own "distinguish endpoint/category" dimension.
	mux.Handle("POST /v1/users", rateLimit(categoryUserAdmin, requirePermission("users:create", users.create)))
	mux.Handle("GET /v1/users", rateLimit(categoryUserAdmin, requirePermission("users:read", users.list)))
	// GET /v1/users/{userId} is deliberately requireAuth only, not
	// requirePermission("users:read", ...): every authenticated user must
	// still be able to view their *own* profile (the existing dashboard's
	// "Account security" card already depends on this — see
	// features/users/useCurrentUser.ts on the frontend), which is not an
	// administrative capability. get() itself checks "is this the
	// caller's own ID, or do they hold users:read" — see that handler's
	// doc comment. Still rate-limited (categoryUserAdmin) — a caller
	// reading their own profile is real load too.
	mux.Handle("GET /v1/users/{userId}", rateLimit(categoryUserAdmin, requireAuth(http.HandlerFunc(users.get))))
	mux.Handle("DELETE /v1/users/{userId}", rateLimit(categoryUserAdmin, requirePermission("users:delete", users.delete)))
	mux.Handle("POST /v1/users/{userId}/disable", rateLimit(categoryUserAdmin, requirePermission("users:disable", users.disable)))
	mux.Handle("POST /v1/users/{userId}/enable", rateLimit(categoryUserAdmin, requirePermission("users:disable", users.enable)))
	mux.Handle("POST /v1/users/{userId}/roles", rateLimit(categoryUserAdmin, requirePermission("roles:update", users.assignRole)))
	mux.Handle("DELETE /v1/users/{userId}/roles/{roleId}", rateLimit(categoryUserAdmin, requirePermission("roles:update", users.removeRole)))

	// --- role/permission read API (Sprint 2.7) ---
	mux.Handle("GET /v1/roles", rateLimit(categoryUserAdmin, requirePermission("roles:read", roles.list)))
	mux.Handle("GET /v1/roles/{roleId}", rateLimit(categoryUserAdmin, requirePermission("roles:read", roles.get)))
	mux.Handle("GET /v1/permissions", rateLimit(categoryUserAdmin, requirePermission("roles:read", roles.listPermissions)))

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
	// Sprint 4 Task 4: list/read use categorySecretsRead, create/update/
	// delete use categorySecretsWrite — a deliberately separate, tighter
	// category for writes (see cmd/server/main.go's own policy
	// construction for the actual limit numbers), per the objective's own
	// "secret reads may require a different policy from writes"
	// instruction. Rate limiting alone is never this codebase's only
	// defense against secret enumeration — authentication,
	// authorization (secrets:* + path policies, Sprint 4 Task 2), and
	// audit logging (Sprint 4 Task 3) all independently already apply to
	// every one of these routes; this is one more layer, not the layer.
	if deps.SecretService != nil {
		secrets := &secretHandler{svc: deps.SecretService}
		mux.Handle("GET /v1/secrets", rateLimit(categorySecretsRead, requirePermission("secrets:list", secrets.list)))
		mux.Handle("POST /v1/secrets", rateLimit(categorySecretsWrite, requirePermission("secrets:create", secrets.create)))
		mux.Handle("GET /v1/secrets/{path...}", rateLimit(categorySecretsRead, requirePermission("secrets:read", secrets.get)))
		mux.Handle("PUT /v1/secrets/{path...}", rateLimit(categorySecretsWrite, requirePermission("secrets:update", secrets.update)))
		mux.Handle("DELETE /v1/secrets/{path...}", rateLimit(categorySecretsWrite, requirePermission("secrets:delete", secrets.delete)))
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
	// Sprint 4 Task 4: every policy-administration route shares
	// categoryPolicyAdmin — including its own read routes (GET
	// /v1/secret-policies, .../assignments), which the objective calls
	// out by name as needing protection against "policy enumeration."
	if deps.SecretPolicyService != nil {
		policies := &secretPolicyHandler{svc: deps.SecretPolicyService}
		mux.Handle("POST /v1/secret-policies", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:create", policies.create)))
		mux.Handle("GET /v1/secret-policies", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:read", policies.list)))
		mux.Handle("GET /v1/secret-policies/{policyId}", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:read", policies.get)))
		mux.Handle("PUT /v1/secret-policies/{policyId}", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:update", policies.update)))
		mux.Handle("DELETE /v1/secret-policies/{policyId}", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:delete", policies.delete)))
		mux.Handle("GET /v1/secret-policies/{policyId}/assignments", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:read", policies.listAssignments)))
		mux.Handle("POST /v1/secret-policies/{policyId}/assignments", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:assign", policies.assign)))
		mux.Handle("DELETE /v1/secret-policies/{policyId}/assignments/{roleId}", rateLimit(categoryPolicyAdmin, requirePermission("secret_policies:assign", policies.unassign)))
	}

	// --- audit log administration (Sprint 4 Task 3): gated on the
	// existing audit:read permission (migrations 000022/000023, already
	// seeded to Security Engineer and Auditor) — reused, not duplicated,
	// per this task's own "extend the existing architecture" instruction.
	// AuditService performs its own internal RBAC check too, the same
	// defense-in-depth double-gate SecretService/SecretPolicyService
	// already have — see that service's own doc comment. ---
	// Sprint 4 Task 4: rate-limited under categoryAuditRead — "audit
	// search should have... rate limiting" per the objective; bounded
	// pagination (max 100/page) and per-request limit validation already
	// exist (dto.AuditLogQuery.Validate, Sprint 4 Task 3); see that type's
	// own doc comment for why no unbounded-retrieval code path exists
	// through this handler at all.
	if deps.AuditService != nil {
		audit := &auditHandler{svc: deps.AuditService}
		mux.Handle("GET /v1/audit-logs", rateLimit(categoryAuditRead, requirePermission("audit:read", audit.list)))
	}

	// --- service account administration (Sprint 5 Task 1): gated on the
	// service_accounts:* / api_keys:* permission catalog (migrations/000030).
	// Every route below shares categoryServiceAccountAdmin, the same
	// "one shared admin-API throttle per resource family" convention
	// categoryUserAdmin/categoryPolicyAdmin already establish. This is
	// entirely separate from the token-exchange route above: that one
	// authenticates a machine caller; these authorize a human
	// administrator managing machine identities and their credentials —
	// never the same request path.
	if deps.ServiceAccountService != nil {
		accounts := &serviceAccountHandler{svc: deps.ServiceAccountService, roles: deps.RoleService, rbac: deps.RBACService}
		mux.Handle("POST /v1/service-accounts", rateLimit(categoryServiceAccountAdmin, requirePermission("service_accounts:create", accounts.create)))
		mux.Handle("GET /v1/service-accounts", rateLimit(categoryServiceAccountAdmin, requirePermission("service_accounts:read", accounts.list)))
		mux.Handle("GET /v1/service-accounts/{serviceAccountId}", rateLimit(categoryServiceAccountAdmin, requirePermission("service_accounts:read", accounts.get)))
		mux.Handle("PATCH /v1/service-accounts/{serviceAccountId}", rateLimit(categoryServiceAccountAdmin, requirePermission("service_accounts:update", accounts.update)))
		mux.Handle("DELETE /v1/service-accounts/{serviceAccountId}", rateLimit(categoryServiceAccountAdmin, requirePermission("service_accounts:delete", accounts.delete)))
		// Role grants reuse roles:update — the same capability
		// users/{id}/roles already gates, just applied to a different
		// principal type, not a second, redundant permission.
		mux.Handle("GET /v1/service-accounts/{serviceAccountId}/roles", rateLimit(categoryServiceAccountAdmin, requirePermission("roles:read", accounts.listRoles)))
		mux.Handle("POST /v1/service-accounts/{serviceAccountId}/roles", rateLimit(categoryServiceAccountAdmin, requirePermission("roles:update", accounts.assignRole)))
		mux.Handle("DELETE /v1/service-accounts/{serviceAccountId}/roles/{roleId}", rateLimit(categoryServiceAccountAdmin, requirePermission("roles:update", accounts.removeRole)))

		keys := &apiKeyHandler{svc: deps.ServiceAccountService}
		mux.Handle("POST /v1/api-keys", rateLimit(categoryServiceAccountAdmin, requirePermission("api_keys:create", keys.create)))
		mux.Handle("GET /v1/api-keys", rateLimit(categoryServiceAccountAdmin, requirePermission("api_keys:read", keys.list)))
		mux.Handle("GET /v1/api-keys/{apiKeyId}", rateLimit(categoryServiceAccountAdmin, requirePermission("api_keys:read", keys.get)))
		mux.Handle("DELETE /v1/api-keys/{apiKeyId}", rateLimit(categoryServiceAccountAdmin, requirePermission("api_keys:delete", keys.delete)))
		mux.Handle("POST /v1/api-keys/{apiKeyId}/rotate", rateLimit(categoryServiceAccountAdmin, requirePermission("api_keys:rotate", keys.rotate)))
	}

	// --- dynamic secret leases (Sprint 5 Task 2): gated on the leases:*
	// permission catalog (migrations/000031), layered on top of the
	// existing secrets:read + path-policy chain — see
	// service.LeaseService.Create's own doc comment for the exact order.
	// GET/renew/revoke additionally allow a lease's own owner regardless
	// of the leases:read/leases:revoke permission (LeaseService's own
	// ownership check) — the rate-limit category and requirePermission
	// gate below apply identically either way; ownership is decided
	// inside the service, never at this routing layer. Registered under
	// the same "nil means don't route it" guard as /v1/secrets: a lease
	// without the Secrets Engine's path-policy machinery to authorize
	// against has nothing to be issued against.
	if deps.LeaseService != nil {
		leases := &leaseHandler{svc: deps.LeaseService}
		mux.Handle("POST /v1/leases", rateLimit(categoryLeaseCreate, requireAuth(http.HandlerFunc(leases.create))))
		mux.Handle("GET /v1/leases", rateLimit(categoryLeaseRead, requireAuth(http.HandlerFunc(leases.list))))
		mux.Handle("GET /v1/leases/{leaseId}", rateLimit(categoryLeaseRead, requireAuth(http.HandlerFunc(leases.get))))
		mux.Handle("POST /v1/leases/{leaseId}/renew", rateLimit(categoryLeaseRenew, requireAuth(http.HandlerFunc(leases.renew))))
		mux.Handle("POST /v1/leases/{leaseId}/revoke", rateLimit(categoryLeaseRevoke, requireAuth(http.HandlerFunc(leases.revoke))))
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
