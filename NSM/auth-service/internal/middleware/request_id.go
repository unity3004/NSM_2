package middleware

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/util"
)

const RequestIDHeader = "X-Request-Id"

// RequestID is where correlation IDs actually originate: it assigns every
// inbound request an ID (or trusts an existing upstream-supplied one, e.g.
// from a load balancer or a service mesh sidecar, so a request traced
// across multiple hops keeps one ID end to end), then does two things with
// it — puts it on the request context directly (RequestIDFromContext,
// which dto.ErrorBody.RequestID and the JSON error envelope read), and
// derives a child logger via base.With(zap.String("request_id", id)) and
// puts *that* on the context too (logging.WithContext).
//
// That second step is the whole mechanism: every log line any handler,
// service, or repository call emits for the rest of this request — by
// calling logging.FromContext(ctx) instead of holding its own logger —
// carries request_id automatically. No function signature in this
// service threads a requestID string through it; the context does that
// job once, here, and nowhere else needs to know it exists.
func RequestID(base *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(RequestIDHeader)
			if id == "" {
				id = "req_" + util.NewUUID()
			}
			w.Header().Set(RequestIDHeader, id)

			ctx := withRequestID(r.Context(), id)
			requestLogger := base.With(zap.String("request_id", id))
			ctx = logging.WithContext(ctx, requestLogger)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
