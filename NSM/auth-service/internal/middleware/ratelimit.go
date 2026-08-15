package middleware

import (
	"context"
	"strconv"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/service"

	"net/http"
)

// RateLimit gates a route behind a general-purpose, Redis-backed request
// throttle (Sprint 4 Task 4) — "how many requests may this identity make
// in this category per window," distinct from RequirePermission's "is
// this identity allowed to do this at all" and from
// AuthAbuseProtection's "has this identity failed too many times" (see
// internal/ratelimit's own package doc comment for that three-way split).
// category is always a compile-time constant supplied at routing time
// ("secrets-read"), the same discipline RequirePermission's own permission
// parameter already follows — never derived from request data.
//
// Identity resolution, in order: an authenticated caller (claims already
// on the request context, placed there by Auth/Authenticate) is counted
// by IdentityUser (or IdentityServiceAccount when claims.SessionID is
// empty — see util.Claims' own doc comment on that being the existing
// signal for "this token has no session," i.e. not a human login) using
// claims.Subject, a stable ID that never changes the way an email address
// can (the objective's own "do not use email as the primary distributed
// rate-limit identity" requirement). An unauthenticated caller (no claims
// yet — e.g. POST /v1/auth/register, which this middleware also gates,
// ahead of any Auth middleware) is counted by IdentityIP instead, using
// the same trusted-proxy-aware util.ResolveClientIP every other IP
// decision in this codebase now goes through (see that function's own
// doc comment on why X-Forwarded-For is never trusted unconditionally).
//
// auditTx may be nil (the same allowance every other AuditTxFunc
// dependency in this codebase makes) — every throttle decision still
// enforces correctly without it, it just doesn't get a rate_limit.exceeded
// audit trail entry.
func RateLimit(limiter ratelimit.APIRateLimiter, auditTx service.AuditTxFunc, category string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := requestIdentity(r)

			decision, err := limiter.Allow(r.Context(), category, identity)
			if err != nil {
				// APIRateLimiter.Allow's own contract (see
				// ratelimit.RedisAPIRateLimiter.Allow's doc comment) is
				// "decide, never hand back a raw failure" — reaching this
				// branch at all would mean that contract was violated by
				// whichever implementation is wired in, a programming
				// error worth loud attention, not a request-by-request
				// decision to make here.
				logging.FromContext(r.Context()).Error("rate limiter returned an unexpected error; failing open for this request",
					zap.String("category", category), zap.Error(err))
				next.ServeHTTP(w, r)
				return
			}

			if !decision.Allowed {
				logging.FromContext(r.Context()).Debug("rate limit exceeded",
					zap.String("category", category), zap.String("identity_type", string(identity.Type)))
				if decision.Transitioned {
					recordRateLimitExceeded(r.Context(), auditTx, category, identity, r)
				}
				retryAfter := int(decision.RetryAfter.Seconds())
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				// Reuses the exact envelope/error-code shape the existing
				// authentication rate limiter's 429 already uses
				// (dto.CodeRateLimited, handler/http/response.go's own
				// RateLimitedError case) — one rate-limit response format
				// across the whole API, not two.
				writeErrorEnvelopeMiddleware(w, r, http.StatusTooManyRequests, dto.CodeRateLimited, "Too many requests. Please try again later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// requestIdentity resolves the RequestIdentity a rate-limit check should
// be counted against for r — see RateLimit's own doc comment for the
// full reasoning.
func requestIdentity(r *http.Request) ratelimit.RequestIdentity {
	if claims, ok := ClaimsFromContext(r.Context()); ok {
		identityType := ratelimit.IdentityUser
		if claims.IsServiceAccount() {
			identityType = ratelimit.IdentityServiceAccount
		}
		return ratelimit.RequestIdentity{Type: identityType, ID: claims.Subject}
	}
	return ratelimit.RequestIdentity{Type: ratelimit.IdentityIP, ID: clientIPMW(r)}
}

// recordRateLimitExceeded is best-effort, matching every other audit
// write in this codebase, and fires only on the transition into a
// throttled state (decision.Transitioned) — never once per repeated
// request against an identity that's already being throttled, which is
// exactly the audit-log-flooding this task's own objective warns
// against. Metadata carries only the category and identity type, never
// the identity's own raw value beyond what ActorID/ResourceID already
// carry (and even those are never a raw IP — see recordRateLimitExceeded's
// own construction below, which only ever sets ActorID for an
// authenticated identity, never an IP address, matching every other
// audit entry in this codebase's own "IPAddress is its own column, never
// duplicated into ActorID" convention).
func recordRateLimitExceeded(ctx context.Context, auditTx service.AuditTxFunc, category string, identity ratelimit.RequestIdentity, r *http.Request) {
	if auditTx == nil {
		return
	}
	var actorID *string
	actorType := entity.AuditActorSystem
	if identity.Type == ratelimit.IdentityUser || identity.Type == ratelimit.IdentityServiceAccount {
		actorType = entity.AuditActorUser
		id := identity.ID
		actorID = &id
	}
	ip := clientIPMW(r)
	requestID := RequestIDFromContext(ctx)

	err := auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    actorType,
			ActorID:      actorID,
			Action:       "rate_limit.exceeded",
			ResourceType: strPtrMW(category),
			Result:       entity.AuditResultDenied,
			IPAddress:    strPtrOrNil(ip),
			RequestID:    strPtrOrNil(requestID),
			Metadata:     map[string]any{"category": category, "identity_type": string(identity.Type)},
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record rate_limit.exceeded audit event",
			zap.String("category", category), zap.Error(err))
	}
}

func strPtrMW(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
