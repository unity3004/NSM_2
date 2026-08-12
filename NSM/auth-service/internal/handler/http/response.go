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
	"strconv"

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
	var limited service.RateLimitedError
	switch {
	case errors.As(err, &locked):
		writeErrorEnvelope(w, r, http.StatusLocked, dto.CodeAccountLocked,
			"Account is locked until "+locked.Until.Format(http.TimeFormat)+".", nil)
	case errors.As(err, &limited):
		// Milestone 6C: Retry-After is a fixed, configured value — never
		// derived from which dimension actually blocked the request or
		// how much of its real window remains, so the header itself
		// carries no information beyond "try again later." No detail
		// about IP/account/pair, Redis, or internal counters reaches the
		// client either way.
		w.Header().Set("Retry-After", strconv.Itoa(int(limited.RetryAfter.Seconds())))
		writeErrorEnvelope(w, r, http.StatusTooManyRequests, dto.CodeRateLimited, "Too many attempts. Please try again later.", nil)
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
	case errors.Is(err, entity.ErrForbidden):
		// Sprint 3 Phase 4: SecretService is the first service to return
		// this sentinel itself (see its own doc comment on why it performs
		// its own RBAC check as well as relying on
		// middleware.RequirePermission) — every route that can reach here
		// is already gated by that middleware too, so in normal operation
		// this case is defense-in-depth, not the primary way a client
		// experiences a 403.
		writeErrorEnvelope(w, r, http.StatusForbidden, dto.CodeForbidden, "You do not have permission to perform this action.", nil)
	case errors.Is(err, entity.ErrTokenExpired):
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeTokenExpired, "Refresh token has expired.", nil)
	case errors.Is(err, entity.ErrTokenReuseDetected):
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeTokenReuseDetected,
			"This refresh token was already rotated. Its entire session family has been revoked.", nil)
	case errors.Is(err, entity.ErrOwnerConflict):
		writeErrorEnvelope(w, r, http.StatusConflict, dto.CodeOwnerConflict, "Exactly one of owner_user_id or owner_service_account_id is required.", nil)
	case errors.Is(err, entity.ErrAlreadyExists):
		writeErrorEnvelope(w, r, http.StatusConflict, dto.CodeConflict, "Resource already exists.", nil)
	case errors.Is(err, entity.ErrVersionConflict):
		// Sprint 3 Phase 4: the secret was updated by someone else between
		// the caller's read and its PUT — see UpdateSecret's own doc
		// comment for why ExpectedVersion (the If-Match header at the HTTP
		// boundary) is mandatory, never optional. A distinct code from
		// CodeConflict on purpose: "re-read and retry" is a different
		// client action than "pick a different path."
		writeErrorEnvelope(w, r, http.StatusConflict, dto.CodeVersionConflict,
			"The secret was updated by someone else; the expected version is no longer current.", nil)
	case errors.Is(err, entity.ErrNotFound):
		writeErrorEnvelope(w, r, http.StatusNotFound, dto.CodeNotFound, "No such resource.", nil)
	case errors.Is(err, util.ErrInvalidSecretPath):
		// Sprint 3 Phase 4: reachable when a path arrives already-invalid
		// on GET/PUT/DELETE /v1/secrets/{path...} — those routes have no
		// request body for a dto.Validate() to catch this earlier (unlike
		// SecretCreateRequest.Validate, which already rejects a bad path
		// before this point on POST). SecretService's own re-validation is
		// what actually catches it either way.
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "Invalid secret path.", nil)
	case errors.Is(err, service.ErrEmptyPayload):
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "Secret payload must not be empty.", nil)
	case errors.Is(err, service.ErrEmptyPolicyRules):
		// Sprint 4 Task 2: reachable if a caller somehow reaches
		// SecretPolicyService with zero rules despite
		// dto.SecretPolicyCreateRequest/SecretPolicyUpdateRequest already
		// rejecting that shape at the DTO boundary (see those types' own
		// Validate methods) — defense-in-depth, the same "the DTO layer
		// normally catches this, but the service's own check must still
		// map to 422, never 500, if it's ever the one that fires" precedent
		// util.ErrInvalidSecretPath's own case above already establishes.
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "A secret policy must have at least one rule.", nil)
	case errors.Is(err, util.ErrInvalidPolicyPattern):
		// Sprint 4 Task 2: a policy rule's path_pattern failed
		// util.ValidatePolicyPathPattern — normally caught first by
		// dto.PolicyRuleRequest.validate, reached here only as
		// defense-in-depth for the same reason the case above is.
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "Invalid secret policy path pattern.", nil)
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
