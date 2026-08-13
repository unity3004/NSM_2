package middleware

import "net/http"

// CORS allows the configured origins to call this API from a browser (the
// admin UI persona from the PRD). It's a middleware rather than per-handler
// headers because the answer to "who may call this" is a deployment-level
// policy, not something any individual endpoint should decide for itself.
//
// allowedOrigins is entirely environment-driven — see
// config.ServerConfig.AllowedOrigins/AUTH_SERVER_ALLOWED_ORIGINS — never a
// literal in this file: what's allowed in local development
// (http://localhost:5173, the Vite dev server) and what's allowed in
// production (the real deployed frontend origin) are two different,
// deployment-specific answers, and this middleware never has to know
// which environment it's running in to make the right call.
//
// A matched origin is echoed back verbatim (never a literal "*"), so this
// is safe to combine with credentialed requests (cookies, or an
// Authorization header sent with `credentials: "include"`) without ever
// widening access to every origin — see MDN's own guidance on why
// `Access-Control-Allow-Origin: *` and credentialed requests don't mix.
// An empty or non-matching allowedOrigins set (the safe default — see
// that config field's own default of []) means no headers are ever set
// at all: a browser then blocks the cross-origin response exactly as
// this middleware's caller intended, not as an accident of
// misconfiguration.
//
// OPTIONS (the preflight browsers send ahead of a "non-simple" request —
// any Content-Type other than the three form/text ones, or a custom
// header like Authorization) is answered here directly, before the
// request ever reaches the mux below: this codebase's router never
// registers an explicit OPTIONS handler for any route, so without this
// short-circuit every preflight would 404.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if allowed[origin] || allowed["*"] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-Organization-Id")
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
