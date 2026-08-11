// Package dto holds the request/response shapes for the HTTP boundary —
// the API contract defined in auth-service-openapi.yaml, translated into Go
// structs. DTOs exist so the HTTP wire format (snake_case JSON, optional
// fields as pointers) never leaks into internal/entity: a column can be
// renamed or an entity reshaped without touching the public API, and the
// API's JSON tags can change without touching business logic.
package dto

// Error is the envelope every non-2xx response uses, matching
// components.schemas.Error in the OpenAPI spec exactly.
type Error struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code      string       `json:"code"`
	Message   string       `json:"message"`
	Details   []FieldError `json:"details,omitempty"`
	RequestID string       `json:"request_id"`
}

type FieldError struct {
	Field string `json:"field"`
	Issue string `json:"issue"`
}

// Error code constants — the same catalog documented in
// auth-service-api-design.md §3, kept as typed constants so a handler can
// never typo a code string.
const (
	CodeMalformedRequest   = "MALFORMED_REQUEST"
	CodeValidationError    = "VALIDATION_ERROR"
	CodeUnauthenticated    = "UNAUTHENTICATED"
	CodeInvalidCredentials = "INVALID_CREDENTIALS"
	CodeMFARequired        = "MFA_REQUIRED"
	CodeAccountLocked      = "ACCOUNT_LOCKED"
	CodeAccountDisabled    = "ACCOUNT_DISABLED"
	CodeForbidden          = "FORBIDDEN"
	CodeNotFound           = "NOT_FOUND"
	CodeConflict           = "CONFLICT"
	CodeOwnerConflict      = "OWNER_CONFLICT"
	// CodeVersionConflict is entity.ErrVersionConflict's wire code (Sprint
	// 3 Phase 4) — deliberately distinct from CodeConflict ("Resource
	// already exists."), which has the wrong meaning for "you updated
	// against a stale version": both map to 409, but a client needs to
	// tell "retry with a different path" apart from "re-read the current
	// version and retry" by machine-readable code, not by parsing the
	// message.
	CodeVersionConflict    = "VERSION_CONFLICT"
	CodeTokenExpired       = "TOKEN_EXPIRED"
	CodeTokenReuseDetected = "TOKEN_REUSE_DETECTED"
	CodeRateLimited        = "RATE_LIMITED"
	CodeInternalError      = "INTERNAL_ERROR"
)

// PageMeta is the pagination footer on every list response.
type PageMeta struct {
	NextCursor *string `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
	Limit      int     `json:"limit"`
}

// ValidationErrors accumulates FieldErrors across a request body so a
// handler can report every problem in one 422 instead of one-at-a-time.
type ValidationErrors []FieldError

func (v *ValidationErrors) Add(field, issue string) {
	*v = append(*v, FieldError{Field: field, Issue: issue})
}

func (v ValidationErrors) Err() error {
	if len(v) == 0 {
		return nil
	}
	return validationError{fields: v}
}

type validationError struct{ fields ValidationErrors }

func (e validationError) Error() string { return "validation failed" }

// Fields recovers the per-field detail from an error produced by
// ValidationErrors.Err, so the HTTP layer can render it without either side
// depending on the other's concrete type.
func Fields(err error) (ValidationErrors, bool) {
	ve, ok := err.(validationError)
	return ve.fields, ok
}
