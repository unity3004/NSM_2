package http

import (
	"net"
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/service"
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

// clientIP returns a bare IP address — never host:port — since every
// caller ultimately stores this in an INET column (sessions, login_history,
// audit_logs), which rejects a port suffix. r.RemoteAddr is always
// "ip:port" in net/http; net.SplitHostPort strips it. X-Forwarded-For, when
// present, is assumed to already be a bare IP (a reverse proxy's own
// header, not something net/http formats for us) and is returned as-is.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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

	result, err := h.svc.RefreshToken(r.Context(), req.RefreshToken, service.LoginMeta{
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
	if err := h.svc.Logout(r.Context(), claims.Subject, claims.SessionID, body.RefreshToken, service.LoginMeta{
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
	}); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
