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

const claimsKey ctxKey = iota

// RequestIDFromContext and withRequestID now delegate to util's own
// storage (Sprint 4 Task 3) — see util.RequestIDFromContext's own doc
// comment for why the primitive moved to a layer both middleware and
// internal/service can reach. This function's name and signature are
// unchanged for every existing caller (response.go's dto.ErrorBody.RequestID,
// in particular); only where the value actually lives changed.
func RequestIDFromContext(ctx context.Context) string {
	return util.RequestIDFromContext(ctx)
}

func withRequestID(ctx context.Context, id string) context.Context {
	return util.WithRequestID(ctx, id)
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
