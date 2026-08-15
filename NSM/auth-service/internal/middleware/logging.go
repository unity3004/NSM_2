package middleware

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/logging"
)

// statusRecorder captures the status code a handler wrote, since
// http.ResponseWriter doesn't expose it after the fact.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Logging emits one structured "http_request" line per request — method,
// path, status, duration — via logging.FromContext, which is why it must
// run *after* RequestID in router.go's chain: it's reading the per-request
// logger RequestID just attached, not the base one. Deliberately not
// where audit_logs or login_history rows get written — those are
// business events the service layer records on purpose, at Info/Warn with
// their own meaning; this is operational telemetry every request gets
// regardless of what it was, logged at Info on success and Warn on a
// 5xx — see the level split below.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		fields := []zap.Field{
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", rec.status),
			zap.Duration("duration", time.Since(start)),
		}
		log := logging.FromContext(r.Context())
		switch {
		case rec.status >= 500:
			// The specific error is already logged, with more context,
			// from internal/handler/http/response.go — this line's job
			// is just to make "how many requests failed" answerable from
			// the access-log stream alone, without joining against
			// anything else.
			log.Warn("http_request", fields...)
		default:
			log.Info("http_request", fields...)
		}
	})
}
