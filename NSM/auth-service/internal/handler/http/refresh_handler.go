package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/service"
)

// refreshHandler implements POST /auth/refresh (Milestone 5B) — deliberately
// its own handler and its own service.RefreshTokenService, distinct from
// authHandler.refresh (POST /v1/auth/token/refresh), which stays wired to
// the pre-existing AuthService.RefreshToken flow; see
// service.RefreshTokenServiceDeps' doc comment for why the two coexist
// rather than one replacing the other in this milestone.
type refreshHandler struct {
	svc *service.RefreshTokenService
}

func (h *refreshHandler) refresh(w http.ResponseWriter, r *http.Request) {
	var req dto.RefreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	result, err := h.svc.Refresh(r.Context(), req.RefreshToken, service.LoginMeta{
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	// dto.TokenResponse has no field a database token hash could ever
	// reach — see that type's own doc comment — and RefreshResult only
	// ever carries raw, freshly-minted secrets, never a stored hash.
	writeJSON(w, r, http.StatusOK, dto.TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		SessionID:    result.SessionID,
	})
}
