package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

type authHandler struct {
	svc *service.AuthService
}

// organizationIDFromRequest resolves the caller's tenant. A production
// build would do this in a dedicated tenant-resolution middleware — from
// the request's subdomain or an API gateway header set after routing — and
// hand it down via context the same way middleware.Auth hands down claims.
// This vertical slice reads a header directly to keep that (real, but
// deployment-specific) piece out of scope; see README.md's "known gaps."
func organizationIDFromRequest(r *http.Request) string {
	return r.Header.Get("X-Organization-Id")
}

func clientIP(r *http.Request) string {
	return util.ResolveClientIP(r)
}

func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	result, err := h.svc.Login(r.Context(), organizationIDFromRequest(r), req.Email, req.Password, service.LoginMeta{
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		SessionID:    result.SessionID,
	})
}

func (h *authHandler) refresh(w http.ResponseWriter, r *http.Request) {
	var req dto.RefreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	result, err := h.svc.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		SessionID:    result.SessionID,
	})
}

func (h *authHandler) logout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken *string `json:"refresh_token,omitempty"`
	}
	// The body is optional on this endpoint (see the OpenAPI spec), so a
	// missing/empty body is not a MALFORMED_REQUEST — only reject it if
	// what *was* sent fails to parse.
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &body) {
			return
		}
	}

	claims, ok := ClaimsFromRequest(r)
	if !ok {
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeUnauthenticated, "Access token is missing or invalid.", nil)
		return
	}
	if err := h.svc.Logout(r.Context(), claims.SessionID, body.RefreshToken); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
