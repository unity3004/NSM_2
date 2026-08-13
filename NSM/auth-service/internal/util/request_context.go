package util

import "context"

// Package-neutral home for the request-ID context primitive (Sprint 4
// Task 3): internal/middleware.RequestID (the only place that actually
// mints or trusts an inbound ID) and internal/service (which needs to read
// it back out to populate entity.AuditLogEntry.RequestID on every audit
// write) must both reach the same value without service depending on
// middleware — a dependency direction this codebase's layering
// (entity -> repository -> service -> handler -> middleware) never allows.
// internal/util already sits below both (middleware imports it for
// util.Claims; every service already imports it for UUIDs/paths/tokens),
// so it's the natural, already-established neutral point for this exact
// kind of cross-cutting context value — the same role it already plays for
// JWT claims and opaque tokens, just for one more thing every layer needs
// to read without owning.
//
// middleware.RequestIDFromContext keeps its own existing name and public
// signature (response.go and every other existing caller are unaffected)
// but now delegates to WithRequestID/RequestIDFromContext here — one
// storage location, two names for the same primitive at two different
// layers, not two independent mechanisms that could disagree.
type requestIDCtxKey struct{}

// WithRequestID returns a context carrying id as "the correlation ID for
// this request." Called exactly once, at the edge, by
// middleware.RequestID — everything downstream reads it back via
// RequestIDFromContext, never sets it again.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDCtxKey{}, id)
}

// RequestIDFromContext returns the correlation ID middleware.RequestID
// attached to ctx, or "" if none was ever attached — e.g. a unit test that
// constructs a service directly, or a background job with no inbound HTTP
// request at all. An audit entry recorded with no request ID simply has
// no RequestID field populated; this is never treated as an error
// anywhere that calls it.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDCtxKey{}).(string); ok {
		return v
	}
	return ""
}
