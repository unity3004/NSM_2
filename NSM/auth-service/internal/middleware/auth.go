package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/util"
)

// Auth verifies the Authorization: Bearer <jwt> header using verifier and
// places the resulting util.Claims on the request context for handlers to
// read via ClaimsFromContext. It is a separate middleware from routing —
// see router.go — so public routes (/auth/login, /auth/token/refresh,
// /service-accounts/{id}/token) can skip it entirely rather than the
// handler having to special-case "no claims present."
func Auth(verifier *util.JWTSigner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			token, ok := strings.CutPrefix(header, "Bearer ")
			if !ok || token == "" {
				writeUnauthenticated(w, r)
				return
			}
			claims, err := verifier.Verify(token)
			if err != nil {
				writeUnauthenticated(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
		})
	}
}

func writeUnauthenticated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(dto.Error{Error: dto.ErrorBody{
		Code:      dto.CodeUnauthenticated,
		Message:   "Access token is missing or invalid.",
		RequestID: RequestIDFromContext(r.Context()),
	}})
}
