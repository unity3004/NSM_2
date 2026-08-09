package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/middleware"
	"github.com/acme/auth-service/internal/service"
)

// logoutHandler implements POST /auth/logout/current (Milestone 6B) —
// requires middleware.Authenticate (6A) to have already run; it is a
// separate route and handler from authHandler.logout (POST
// /v1/auth/logout), which stays wired to the pre-existing AuthService.Logout
// flow and the old middleware.Auth. See service.LogoutService's own doc
// comment for why the session to revoke is read only from the request
// context, never the request body.
type logoutHandler struct {
	svc *service.LogoutService
}

func (h *logoutHandler) logout(w http.ResponseWriter, r *http.Request) {
	identity, ok := middleware.IdentityFromContext(r.Context())
	if !ok {
		// middleware.Authenticate always sets this before calling next;
		// reaching here without it means this handler was reached
		// without that middleware running — a routing bug, not a client
		// mistake, but still reported as the same generic 401 a real
		// authentication failure would produce, never a 500 that would
		// hint at server-side wiring detail.
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeUnauthenticated, "Access token is missing or invalid.", nil)
		return
	}

	err := h.svc.Logout(r.Context(), identity.Subject, identity.SessionID, service.LoginMeta{
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	// A simple success response, per this milestone's own API-response
	// requirement: no access token, refresh token, or session identifier
	// the client doesn't already have.
	w.WriteHeader(http.StatusNoContent)
}
