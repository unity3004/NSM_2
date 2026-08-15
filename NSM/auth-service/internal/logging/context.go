package logging

import (
	"context"

	"go.uber.org/zap"
)

type ctxKey int

const loggerKey ctxKey = iota

// WithContext returns a context carrying l as "the logger for this
// request." middleware.RequestID is the only place that should call this
// in normal operation — it does so once, right after minting or trusting
// a request ID, having already called l.With(zap.String("request_id", id)).
// Every log line produced by anything that pulls its logger back out via
// FromContext therefore carries that field without repeating it — that's
// the entire mechanism correlation IDs rely on here: attach once, near
// the edge; read many times, everywhere inside.
func WithContext(ctx context.Context, l *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext returns the request-scoped logger, or the global logger
// (zap.L()) if none was attached — the fallback that keeps a background
// job, a startup-time log line, or a test that never ran RequestID from
// needing a nil check at every call site.
func FromContext(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(loggerKey).(*zap.Logger); ok {
		return l
	}
	return zap.L()
}
