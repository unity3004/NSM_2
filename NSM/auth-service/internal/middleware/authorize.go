package middleware

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/service"
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
func RequirePermission(rbac *service.RBACService, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeUnauthenticated(w, r)
				return
			}

			allowed, err := rbac.HasPermission(r.Context(), claims.Subject, permission)
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
				writeErrorEnvelopeMiddleware(w, r, http.StatusForbidden, dto.CodeForbidden, "You do not have permission to perform this action.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
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
