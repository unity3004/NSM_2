// Package http adapts HTTP requests to internal/service calls and service
// results back to the JSON shapes in internal/dto. This is the outermost
// ring of the architecture — the "delivery mechanism" in Clean
// Architecture terms — which is why it's the only layer allowed to import
// net/http: swap it for a gRPC package under internal/handler/grpc and
// nothing in internal/service or below would need to change.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/middleware"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// ClaimsFromRequest is the handler-side wrapper around
// middleware.ClaimsFromContext, kept here so handler files only ever
// import "github.com/acme/auth-service/internal/handler/http" helpers, not
// middleware directly.
func ClaimsFromRequest(r *http.Request) (*util.Claims, bool) {
	return middleware.ClaimsFromContext(r.Context())
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func writeErrorEnvelope(w http.ResponseWriter, r *http.Request, status int, code, message string, details []dto.FieldError) {
	writeJSON(w, r, status, dto.Error{Error: dto.ErrorBody{
		Code:      code,
		Message:   message,
		Details:   details,
		RequestID: middleware.RequestIDFromContext(r.Context()),
	}})
}

// decodeJSON reads and unmarshals the request body, reporting a
// MALFORMED_REQUEST (400) — not a VALIDATION_ERROR (422) — because a body
// that isn't even valid JSON never got far enough to have field-level
// problems. See auth-service-api-design.md §3 for the 400-vs-422 rule this
// enforces.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		writeErrorEnvelope(w, r, http.StatusBadRequest, dto.CodeMalformedRequest, "Request body is required.", nil)
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErrorEnvelope(w, r, http.StatusBadRequest, dto.CodeMalformedRequest, "Request body is not valid JSON: "+err.Error(), nil)
		return false
	}
	return true
}

// writeValidationError reports the field-level issues a dto.Validate()
// call collected. It only knows how to unpack dto.ValidationErrors — any
// other error reaching here is a handler bug, not a client mistake.
func writeValidationError(w http.ResponseWriter, r *http.Request, err error) {
	fields, ok := dto.Fields(err)
	if !ok {
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "Request failed validation.", nil)
		return
	}
	writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "Request failed validation.", fields)
}

// writeServiceError is the single place a domain/service error becomes an
// HTTP response — the mapping documented in auth-service-api-design.md's
// error code catalog, implemented exactly once so no two handlers can
// disagree about what ErrAccountLocked means on the wire.
func writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var locked service.AccountLockedError
	switch {
	case errors.As(err, &locked):
		writeErrorEnvelope(w, r, http.StatusLocked, dto.CodeAccountLocked,
			"Account is locked until "+locked.Until.Format(http.TimeFormat)+".", nil)
	case errors.Is(err, service.ErrMissingSessionIdentity):
		// The authenticated identity had no session ID to act on — an
		// authentication/session design error (Milestone 6B requirement
		// #23), reported identically to any other authentication
		// failure: the same code and message writeUnauthenticated itself
		// uses, never a distinct signal a client could use to tell "your
		// token structurally can't be used for this" apart from "your
		// token is simply invalid."
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeUnauthenticated, "Access token is missing or invalid.", nil)
	case errors.Is(err, entity.ErrInvalidCredentials):
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeInvalidCredentials, "Email or password is incorrect.", nil)
	case errors.Is(err, entity.ErrAccountDisabled):
		writeErrorEnvelope(w, r, http.StatusForbidden, dto.CodeAccountDisabled, "Account is disabled.", nil)
	case errors.Is(err, entity.ErrTokenExpired):
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeTokenExpired, "Refresh token has expired.", nil)
	case errors.Is(err, entity.ErrTokenReuseDetected):
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeTokenReuseDetected,
			"This refresh token was already rotated. Its entire session family has been revoked.", nil)
	case errors.Is(err, entity.ErrOwnerConflict):
		writeErrorEnvelope(w, r, http.StatusConflict, dto.CodeOwnerConflict, "Exactly one of owner_user_id or owner_service_account_id is required.", nil)
	case errors.Is(err, entity.ErrAlreadyExists):
		writeErrorEnvelope(w, r, http.StatusConflict, dto.CodeConflict, "Resource already exists.", nil)
	case errors.Is(err, entity.ErrNotFound):
		writeErrorEnvelope(w, r, http.StatusNotFound, dto.CodeNotFound, "No such resource.", nil)
	default:
		// Anything else is unmapped — middleware.Recover would also catch
		// a panic, but a plain returned error should still become a clean
		// 500 rather than propagate as a Go error onto an already-written
		// response. Logged at Error here, not just left to
		// middleware.Logging's Warn-on-5xx line: that line only has a
		// status code, not the Go error that caused it, and "an
		// unexpected error occurred" on the wire must never be the last
		// word an on-call engineer gets about what actually happened.
		logging.FromContext(r.Context()).Error("unmapped service error", zap.Error(err))
		writeErrorEnvelope(w, r, http.StatusInternalServerError, dto.CodeInternalError, "An unexpected error occurred.", nil)
	}
}
