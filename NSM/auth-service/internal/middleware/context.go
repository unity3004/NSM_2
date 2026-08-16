// Package middleware holds cross-cutting HTTP concerns — request
// identification, panic recovery, logging, authentication, CORS — that
// apply uniformly across handlers and have no business-logic content of
// their own. Keeping them out of internal/handler is what lets a handler
// file be *only* "translate this HTTP request into a service call," with
// every request that never should have reached it (unauthenticated, no
// request ID yet) filtered out one layer up.
package middleware

import (
	"context"

	"github.com/acme/auth-service/internal/util"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	claimsKey
)

func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// ClaimsFromContext returns the verified JWT claims Auth middleware placed
// on the request context, if any. Handlers use this instead of
// re-parsing the Authorization header themselves.
func ClaimsFromContext(ctx context.Context) (*util.Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*util.Claims)
	return c, ok
}

func withClaims(ctx context.Context, c *util.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}
