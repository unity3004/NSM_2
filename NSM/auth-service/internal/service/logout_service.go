package service

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
)

// ErrMissingSessionIdentity is returned when the authenticated identity
// presented to Logout has no session ID (or, defensively, no user ID) at
// all. Per Milestone 6B's own requirement, this is treated as an
// authentication/session *design* error — something upstream should
// never have let happen — never as "revoke nothing and silently
// succeed," and never as a hint to guess which session was meant.
// security.AccessTokenClaims now carries a session claim (`sid` — see
// that type's own doc comment) for every token RefreshTokenService.Refresh
// mints, so a real caller no longer hits this path; it remains a defensive
// guard for any future access-token issuer that legitimately has no
// session to name (e.g. a service-account token).
var ErrMissingSessionIdentity = errors.New("service: authenticated identity has no session ID")

// LogoutServiceDeps wires LogoutService to the abstractions Milestone 6B
// reuses rather than duplicates: *SessionService (revocation, ownership
// enforcement, and idempotency all already live there — see
// SessionService.RevokeSession) and the same AuditTxFunc pattern
// AuthService/RefreshTokenService already use for their own audit
// writes. SessionService itself stays audit-agnostic on purpose: adding
// an audit dependency there would force every caller (including
// RefreshTokenService's own reuse-detection revocation) to either share
// or duplicate an audit action, when each use case's audit event
// actually means something different.
type LogoutServiceDeps struct {
	Sessions *SessionService
	AuditTx  AuditTxFunc
}

type LogoutService struct {
	deps LogoutServiceDeps
}

func NewLogoutService(deps LogoutServiceDeps) *LogoutService {
	return &LogoutService{deps: deps}
}

// Logout revokes callerUserID's own sessionID. Both values must come from
// the caller's already-validated identity (middleware.Authenticate,
// Milestone 6A) — never from a request body, which is why this method
// takes plain strings rather than an *http.Request: there is no path
// through this function that reads anything else. SessionService.RevokeSession's
// own ownership check is the second, independent enforcement of that
// same rule (a sessionID belonging to a different user is rejected
// there, identically to a nonexistent one).
//
// Idempotent: revoking an already-revoked session succeeds the same way
// a first logout does, since it delegates entirely to
// SessionService.RevokeSession's own idempotency.
//
// This never directly touches refresh_tokens. RefreshTokenService.Refresh
// already checks the session's live state via SessionService.ValidateSession
// before allowing a rotation (Milestone 5B) — so revoking the session
// here is what invalidates every refresh token tied to it, through
// session state, not through a second write this method would otherwise
// need to keep transactionally consistent with the first.
func (s *LogoutService) Logout(ctx context.Context, callerUserID, sessionID string, meta LoginMeta) error {
	var logoutErr error
	defer func() {
		s.recordLogoutAudit(ctx, callerUserID, sessionID, logoutErr, meta)
	}()

	if callerUserID == "" || sessionID == "" {
		logoutErr = ErrMissingSessionIdentity
		return logoutErr
	}

	if err := s.deps.Sessions.RevokeSession(ctx, callerUserID, sessionID, entity.RevocationLogout); err != nil {
		logoutErr = err
		return logoutErr
	}

	// user_id only, never the session ID — the same "avoid full session
	// IDs in logs where avoidable" restraint SessionService.CreateSession
	// already keeps.
	logging.FromContext(ctx).Info("logout", zap.String("user_id", callerUserID))
	return nil
}

// recordLogoutAudit best-effort appends one audit_logs row per logout
// attempt — Action "auth.logout", Result varying, Metadata carrying only
// a failure reason string on failure. A failure here is logged and
// swallowed, never surfaced to the caller, the same convention every
// other audit write in this codebase already follows.
func (s *LogoutService) recordLogoutAudit(ctx context.Context, userID, sessionID string, logoutErr error, meta LoginMeta) {
	if s.deps.AuditTx == nil {
		return
	}

	result := entity.AuditResultSuccess
	metadata := map[string]any{}
	if logoutErr != nil {
		result = entity.AuditResultFailure
		metadata["failure_reason"] = logoutFailureReason(logoutErr)
	}

	var actorID, resourceID *string
	if userID != "" {
		actorID = &userID
	}
	if sessionID != "" {
		resourceID = &sessionID
	}

	audit := &entity.AuditLogEntry{
		ActorType:    entity.AuditActorUser,
		ActorID:      actorID,
		Action:       "auth.logout",
		ResourceType: strPtr("session"),
		ResourceID:   resourceID,
		Result:       result,
		IPAddress:    strPtr(meta.IPAddress),
		Metadata:     metadata,
	}
	err := s.deps.AuditTx(ctx, func(repo repository.AuditLogRepository) error {
		return repo.Append(ctx, audit)
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record logout audit event", zap.Error(err))
	}
}

func logoutFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrMissingSessionIdentity):
		return "missing_session_identity"
	case errors.Is(err, entity.ErrNotFound):
		return "session_not_found_or_not_owned"
	default:
		return "error"
	}
}
