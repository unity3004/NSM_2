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
	// ErrForbidden means the caller is authenticated but lacks the
	// permission a service-layer operation requires. Every other write in
	// this codebase relies entirely on middleware.RequirePermission to
	// reject an unauthorized request before a service method ever runs
	// (see that middleware's own doc comment) — SecretService
	// (Sprint 3 Phase 3) is the first service to perform its own RBAC
	// check internally, because it must be safely callable — and safely
	// reject an unauthorized caller — with no HTTP/middleware layer in
	// front of it at all yet.
	ErrForbidden = errors.New("insufficient permissions")
	// ErrVersionConflict means an update supplied an expected current
	// version that no longer matches — another writer's update already
	// landed first. See repository.SecretRepository's
	// CreateVersionIfCurrent for the transactional check that produces
	// this, and SecretService.UpdateSecret for how a caller is expected to
	// react (re-read the current version and retry, or surface a 409 to
	// its own caller — never silently overwrite).
	ErrVersionConflict = errors.New("secret was updated by someone else; expected version is stale")
	// ErrInvalidServiceAccountCredential covers every way a machine-auth
	// credential can fail to verify — unknown, wrong secret, wrong owning
	// service account, revoked, or expired — collapsed into one error for
	// the same anti-enumeration reason ErrInvalidCredentials collapses
	// every human-login failure mode: a caller must never be able to tell
	// "no such credential" apart from "credential exists but is expired"
	// through the response alone.
	ErrInvalidServiceAccountCredential = errors.New("invalid service account credentials")
)
