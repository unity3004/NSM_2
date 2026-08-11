package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/service"
)

type platformHandler struct {
	svc *service.BootstrapService
}

// status implements GET /v1/platform/status — unauthenticated by design
// (a client asking this question, by definition, may not have a token
// yet) and deliberately the only thing this response says. See
// dto.PlatformStatusResponse's own doc comment for what it must never
// reveal.
func (h *platformHandler) status(w http.ResponseWriter, r *http.Request) {
	initialized, err := h.svc.Initialized(r.Context())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.PlatformStatusResponse{Initialized: initialized})
}

// bootstrap implements POST /v1/platform/bootstrap — creates the
// platform's first administrator. Unauthenticated by design, the same way
// POST /auth/register is: there is no token to require from a caller who,
// by construction, cannot possibly hold one yet. See
// service.BootstrapService.Bootstrap for the atomicity and race-condition
// guarantees; a losing concurrent request lands in writeServiceError's
// entity.ErrAlreadyExists case below, reported as 409 CONFLICT with the
// same generic message a second registration against an existing email
// would get — never "you lost a race," which would confirm to an
// unauthenticated caller that a bootstrap attempt happened at all.
func (h *platformHandler) bootstrap(w http.ResponseWriter, r *http.Request) {
	var req dto.BootstrapRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	u, err := h.svc.Bootstrap(r.Context(), service.BootstrapInput{
		Username:  req.Username,
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.BootstrapResponse{
		ID:        u.ID,
		Username:  *u.Username,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
	})
}
