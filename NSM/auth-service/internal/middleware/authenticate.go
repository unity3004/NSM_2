package middleware

import (
	"context"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/security"
)

// AuthenticatedIdentity is what Authenticate places on the request
// context after a token validates — deliberately minimal, matching
// exactly what security.AccessTokenClaims actually carries (iss/sub/aud/
// iat/exp/jti, per that type's own doc comment). It is not util.Claims
// (the pre-existing Auth middleware's identity type, below): that type's
// OrganizationID/SessionID/Permissions fields describe the old HS256
// implementation's richer, session-linked claim shape, which the new
// access tokens this middleware validates don't carry — reusing it here
// would mean fabricating fields, not reusing an abstraction. There is
// deliberately no IdentityType field either: nothing today mints an
// access token for anything but a user subject (service-account token
// issuance is a later, explicitly separate milestone), so a type
// distinction would describe a capability that doesn't exist yet.
type AuthenticatedIdentity struct {
	// Subject is the token's `sub` claim.
	Subject string
	// SessionID is populated only if a future claim design adds one —
	// security.AccessTokenClaims doesn't carry one today, so this is
	// always empty for now. Kept as a field so downstream code that will
	// eventually want it doesn't need a breaking signature change later.
	SessionID string
	// TokenID is the token's `jti` claim. Like the token itself, this is
	// never logged in full anywhere in this package.
	TokenID string
}

type identityCtxKey int

const authenticatedIdentityKey identityCtxKey = 0

// IdentityFromContext returns the identity Authenticate placed on the
// request context, if any — the one way a downstream handler learns who
// made the request. There is no way to retrieve a raw token string
// through this accessor: AuthenticatedIdentity has no field for one, and
// WithIdentity below is the only code that writes to
// authenticatedIdentityKey.
func IdentityFromContext(ctx context.Context) (AuthenticatedIdentity, bool) {
	id, ok := ctx.Value(authenticatedIdentityKey).(AuthenticatedIdentity)
	return id, ok
}

// WithIdentity returns a context carrying id — exported for the same
// reason logging.WithContext is: a handler-level test (Milestone 6B's
// logout_handler_test.go, for one) needs to place a fully-controlled
// identity on a request context without running a real token through
// Authenticate first, and any future non-HTTP caller that already has a
// validated identity from elsewhere would need the same seam.
func WithIdentity(ctx context.Context, id AuthenticatedIdentity) context.Context {
	return context.WithValue(ctx, authenticatedIdentityKey, id)
}

// Authenticate verifies the Authorization: Bearer <access-token> header
// using tokens (security.TokenService, Milestone 5A) and places the
// resulting AuthenticatedIdentity on the request context for
// IdentityFromContext to retrieve. audience is the value every call
// passes to TokenService.ValidateAccessToken — the same audience this
// service's own token-issuing paths mint for (see
// config.AccessTokenConfig.DefaultAudience).
//
// This is a distinct middleware from Auth (auth.go), which still backs
// the pre-existing HS256 token flow issued by AuthService.Login/
// RefreshToken — see this milestone's own report for why the two coexist
// rather than one replacing the other; no existing route is rewired to
// use this middleware in this milestone.
//
// Every rejection reason — missing header, wrong scheme, malformed
// token, bad signature, wrong algorithm, wrong issuer/audience, expired,
// missing required claims — produces the exact same 401 UNAUTHENTICATED
// response via writeUnauthenticated (shared with Auth); the specific
// reason never reaches the client, and this function performs no
// authorization or permission check of any kind. A request that reaches
// the next handler is known only to be *from someone*, never *allowed to
// do this*.
func Authenticate(tokens *security.TokenService, audience string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				writeUnauthenticated(w, r)
				return
			}

			claims, err := tokens.ValidateAccessToken(token, audience)
			if err != nil {
				// Debug, not Warn: an expired or otherwise no-longer-valid
				// access token is an expected, routine occurrence (a
				// client that hasn't refreshed yet), the same
				// classification Login already applies to one wrong
				// password — see auth_service.go's identical reasoning.
				// zap.Error(err) never contains the token itself: every
				// error TokenService.ValidateAccessToken can return is a
				// static sentinel or a library error describing *why*,
				// never echoing the input.
				logging.FromContext(r.Context()).Debug("access token validation failed", zap.Error(err))
				writeUnauthenticated(w, r)
				return
			}

			identity := AuthenticatedIdentity{
				Subject: claims.Subject,
				TokenID: claims.ID,
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), identity)))
		})
	}
}

// bearerToken extracts the token from an Authorization: Bearer <token>
// header without modifying it in any way — no trimming beyond the exact
// "Bearer " scheme prefix, no case changes to the token itself. Every
// failure mode (header absent, wrong scheme, no token after the scheme)
// reports the same ok=false; Authenticate collapses all of them into one
// 401, so this function's only job is "did we find a bearer token."
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || scheme != "Bearer" || token == "" {
		return "", false
	}
	return token, true
}
