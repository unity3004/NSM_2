package middleware

import (
	"encoding/json"
	"net/http"
	"runtime/debug"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/logging"
)

// Recover converts a panic anywhere downstream into a 500 INTERNAL_ERROR
// envelope instead of a dropped connection. It is intentionally the
// outermost middleware in router.go's chain, so a panic in RequestID or
// Logging itself — not just in a handler — is still caught; a panic that
// early means logging.FromContext falls back to the global logger (see
// that function's doc comment), which is exactly the graceful-degradation
// behavior that fallback exists for.
//
// A recovered panic is always logged at Error, never Warn or below: by
// definition, something violated an invariant the code assumed always
// held. debug.Stack() is captured explicitly here rather than relied on
// via zap's AddStacktrace(ErrorLevel) — that option captures the stack at
// the *log call site* (inside this defer), which would just point at
// recover.go; debug.Stack() called here captures the goroutine's actual
// unwind, which points at the real bug.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logging.FromContext(r.Context()).Error("panic recovered",
					zap.Any("panic", rec),
					zap.String("stack", string(debug.Stack())),
				)
				writeInternalError(w, r)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// writeInternalError is a minimal local copy of the response envelope
// logic in internal/handler/http/response.go. It's duplicated rather than
// shared because middleware must not import handler (handler already
// imports middleware to build its chain — the other direction would be a
// cycle), and it's small enough that duplicating it is cheaper than adding
// a third package just to break the cycle.
func writeInternalError(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(dto.Error{Error: dto.ErrorBody{
		Code:      dto.CodeInternalError,
		Message:   "An unexpected error occurred.",
		RequestID: RequestIDFromContext(r.Context()),
	}})
}
