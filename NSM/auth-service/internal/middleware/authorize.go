package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// RequirePermission gates a route behind a real-time, database-backed
// authorization check — the first such gate in this codebase (see
// service.RBACService's own doc comment). It must run after Auth (or
// Authenticate) in the middleware chain: it reads the caller's identity
// from the request context those middlewares place there, never from
// anything the request itself claims about who it is or what role it
// has. permission is always a compile-time constant supplied at routing
// time ("users:create"), never derived from request data — there is no
// code path through this function that a client could influence which
// permission gets checked.
//
// A caller with no verified identity on the context (Authenticate never
// ran, or ran and found nothing) is reported identically to Auth's own
// writeUnauthenticated — a routing/wiring bug, not something a request
// should be able to distinguish from "no token presented at all".
//
// auditTx (Sprint 4 Task 3) records "authorization.denied" on every 403
// this middleware produces — the single chokepoint every permission-gated
// route in this codebase passes through, for every resource (users,
// roles, secrets, secret_policies, audit itself), not only the ones a
// service happens to also self-check internally. Before this, a 403 from
// here (the caller's actual experience for the overwhelming majority of
// denied requests — see SecretService.authorizeSecretAccess's own doc
// comment on why its internal recheck is normally unreachable once
// middleware already gated the route) left no audit trail at all; only
// SecretService's own internal path-policy denial did (secret.access_denied,
// Sprint 4 Task 2). auditTx may be nil (the same allowance every other
// AuditTxFunc dependency in this codebase makes) — every denial still
// enforces correctly, it just doesn't get an audit trail entry.
func RequirePermission(rbac *service.RBACService, auditTx service.AuditTxFunc, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeUnauthenticated(w, r)
				return
			}

			var allowed bool
			var err error
			// Sprint 5 Task 1: a service-account-issued token's Subject is
			// an entity.ServiceAccount.ID, not a User.ID — dispatching on
			// claims.IsServiceAccount() (backed by the same SessionID
			// signal machine tokens carry by construction, see that
			// method's own doc comment) is what keeps this middleware from
			// ever checking user_roles for a subject that only exists in
			// service_account_roles, which would silently and permanently
			// deny every service account regardless of its actual grants.
			if claims.IsServiceAccount() {
				allowed, err = rbac.HasServiceAccountPermission(r.Context(), claims.Subject, permission)
			} else {
				allowed, err = rbac.HasPermission(r.Context(), claims.Subject, permission)
			}
			if err != nil {
				// Fail closed: a database problem answering "is this
				// allowed" must never be treated as "yes." Logged at
				// Error since this is either a real infrastructure
				// problem or (see RBACService.HasPermission) a
				// programming error in how this middleware was wired up
				// — either way, worth a human's attention, unlike an
				// ordinary, expected denial below.
				logging.FromContext(r.Context()).Error("authorization check failed",
					zap.String("permission", permission), zap.Error(err))
				writeErrorEnvelopeMiddleware(w, r, http.StatusInternalServerError, dto.CodeInternalError, "An unexpected error occurred.")
				return
			}
			if !allowed {
				logging.FromContext(r.Context()).Debug("access denied",
					zap.String("user_id", claims.Subject), zap.String("permission", permission))
				recordAuthorizationDenied(r.Context(), auditTx, claims.Subject, claims.IsServiceAccount(), permission, r, organizationIDMW(r))
				writeErrorEnvelopeMiddleware(w, r, http.StatusForbidden, dto.CodeForbidden, "You do not have permission to perform this action.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// recordAuthorizationDenied is best-effort, matching every other audit
// write in this codebase — a Postgres problem recording that a request
// was denied must never itself change the response the caller already
// correctly got (403). ResourceType is the permission's own resource
// segment ("secrets" out of "secrets:read") — the only "what was this
// about" this generic layer can name without resolving a specific row;
// ResourceID is the request path, which is a more specific, genuinely
// useful correlation hint (which route, not just which resource family)
// that costs nothing extra to capture here. Metadata carries the full
// permission string and HTTP method — never anything from the request
// body, which this middleware never reads.
func recordAuthorizationDenied(ctx context.Context, auditTx service.AuditTxFunc, actorID string, isServiceAccount bool, permission string, r *http.Request, organizationID string) {
	if auditTx == nil {
		return
	}
	resource, _, _ := strings.Cut(permission, ":")
	actor := actorID
	path := r.URL.Path
	requestID := RequestIDFromContext(ctx)
	ip := clientIPMW(r)
	// Sprint 5 Task 1: a denied service-account request is attributed to
	// AuditActorServiceAccount, never AuditActorUser — the same dispatch
	// RequirePermission's own permission check above already makes, kept
	// in sync here so a request's audit trail always agrees with which
	// RBAC table actually decided it.
	actorType := entity.AuditActorUser
	if isServiceAccount {
		actorType = entity.AuditActorServiceAccount
	}

	err := auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: strPtrOrNil(organizationID),
			ActorType:      actorType,
			ActorID:        &actor,
			Action:         "authorization.denied",
			ResourceType:   &resource,
			ResourceID:     &path,
			Result:         entity.AuditResultDenied,
			IPAddress:      strPtrOrNil(ip),
			RequestID:      strPtrOrNil(requestID),
			Metadata:       map[string]any{"permission": permission, "method": r.Method},
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record authorization.denied audit event",
			zap.String("permission", permission), zap.Error(err))
	}
}

// organizationIDMW mirrors handler/http/auth_handler.go's
// organizationIDFromRequest — see clientIPMW's own doc comment just below
// for why this package keeps a small, local duplicate of that one-liner
// rather than importing internal/handler/http (which already imports this
// package, so the reverse dependency would be a cycle).
func organizationIDMW(r *http.Request) string {
	return r.Header.Get("X-Organization-Id")
}

// clientIPMW mirrors handler/http/auth_handler.go's clientIP — both now
// delegate to util.ResolveClientIP (Sprint 4 Task 4), the single place
// this codebase decides which IP a request is actually from; see that
// function's own doc comment for why X-Forwarded-For/X-Real-IP are only
// ever trusted when the request's direct peer is itself a configured
// trusted proxy. This wrapper's own name stays local to this package for
// the same "small, deliberate duplication instead of an import cycle"
// reason writeErrorEnvelopeMiddleware's own doc comment already documents
// for this file: internal/handler/http imports internal/middleware, so
// the reverse dependency can't exist.
func clientIPMW(r *http.Request) string {
	return util.ResolveClientIP(r)
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// writeErrorEnvelopeMiddleware mirrors handler/http/response.go's
// writeErrorEnvelope exactly (same dto.Error envelope, same
// RequestIDFromContext propagation) — duplicated rather than imported
// because internal/handler/http already imports internal/middleware, and
// this package must never import back, or every handler package that
// imports middleware would gain a compile-time dependency cycle. The
// existing Auth middleware's writeUnauthenticated already establishes
// this exact "small, deliberate duplication instead of a cycle" precedent
// in this same package.
func writeErrorEnvelopeMiddleware(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dto.Error{Error: dto.ErrorBody{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFromContext(r.Context()),
	}})
}
