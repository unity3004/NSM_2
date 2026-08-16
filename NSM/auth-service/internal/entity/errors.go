package entity

import "errors"

// Sentinel domain errors. These are the innermost layer of the architecture:
// repositories return them instead of driver-specific errors (sql.ErrNoRows,
// a pq unique-violation code), and handlers translate them to the exact HTTP
// status + error code catalog defined in auth-service-openapi.yaml — so the
// mapping from "what went wrong" to "what the API says" happens in exactly
// one place (internal/handler/http/response.go), not scattered across every
// call site.
var (
	ErrNotFound           = errors.New("resource not found")
	ErrAlreadyExists      = errors.New("resource already exists")
	ErrInvalidCredentials = errors.New("email or password is incorrect")
	ErrAccountLocked      = errors.New("account is locked")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenReuseDetected = errors.New("refresh token was already rotated")
	ErrOwnerConflict      = errors.New("exactly one owner must be set")
	ErrSessionRevoked     = errors.New("session has been revoked")
	ErrSessionExpired     = errors.New("session has expired")
	ErrRateLimited        = errors.New("too many attempts")
)
