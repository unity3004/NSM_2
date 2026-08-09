package service

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// DefaultSessionTTL is used when CreateSessionInput.TTL is zero — the same
// duration AuthService.issueSession derives from cfg.JWT.RefreshTokenTTL
// today. A caller that needs a different lifetime sets TTL explicitly.
const DefaultSessionTTL = 30 * 24 * time.Hour

// SessionService owns session lifecycle operations — creation, lookup,
// validation, and revocation — as its own concern, with per-user
// authorization enforced at this boundary. It depends on only
// repository.SessionRepository, never repository.UserRepository:
// sessions.user_id's foreign key to users(id) is the actual enforcement
// that a session belongs to a real user (see
// postgres.translateError's foreign-key-violation case), the same "trust
// the constraint" choice UserService.Register already makes for
// email/username uniqueness rather than a redundant existence check.
type SessionService struct {
	sessions repository.SessionRepository
}

func NewSessionService(sessions repository.SessionRepository) *SessionService {
	return &SessionService{sessions: sessions}
}

// CreateSessionInput is CreateSession's argument. IPAddress/UserAgent/
// DeviceFingerprint are request metadata the caller already has — the
// same fields LoginMeta carries for AuthService.Login — never anything
// secret.
type CreateSessionInput struct {
	UserID            string
	IPAddress         string
	UserAgent         string
	DeviceFingerprint string
	// TTL is the session's lifetime from now. Zero means DefaultSessionTTL.
	TTL time.Duration
}

// CreatedSession is CreateSession's result. RawToken is the bearer secret
// the caller must hand back to the client exactly once (a cookie, a
// response field) and never log or persist anywhere else: only its
// SHA-256 (Session.SessionTokenHash) is stored, via the same
// util.HashToken convention AuthService.issueSession already uses for
// this table.
type CreatedSession struct {
	Session  *entity.Session
	RawToken string
}

// CreateSession mints a new session for an existing user. It does not
// pre-check that UserID refers to a real row; a nonexistent user surfaces
// as entity.ErrNotFound from the repository's foreign-key translation,
// never a raw Postgres error.
func (s *SessionService) CreateSession(ctx context.Context, in CreateSessionInput) (*CreatedSession, error) {
	raw, err := util.NewOpaqueToken()
	if err != nil {
		return nil, err
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	session := &entity.Session{
		UserID:            in.UserID,
		SessionTokenHash:  util.HashToken(raw),
		IPAddress:         strPtr(in.IPAddress),
		UserAgent:         strPtr(in.UserAgent),
		DeviceFingerprint: strPtr(in.DeviceFingerprint),
		ExpiresAt:         time.Now().Add(ttl),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}

	// user_id only, never the session ID — see this milestone's report on
	// avoiding full session IDs in logs where avoidable.
	logging.FromContext(ctx).Info("session created", zap.String("user_id", in.UserID))
	return &CreatedSession{Session: session, RawToken: raw}, nil
}

// GetSession returns callerUserID's own session by ID. A session that
// exists but belongs to a different user is reported identically to one
// that doesn't exist at all — entity.ErrNotFound either way — the same
// anti-enumeration collapse AuthService.Login applies to "no such email"
// vs. "wrong password": whether some other user's session exists must not
// be a distinguishable outcome from this caller's perspective.
func (s *SessionService) GetSession(ctx context.Context, callerUserID, sessionID string) (*entity.Session, error) {
	session, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.UserID != callerUserID {
		return nil, entity.ErrNotFound
	}
	return session, nil
}

// ValidateSession reports whether sessionID is currently valid to
// authenticate with, and if so, returns it — including the UserID a
// caller resolving an incoming session token doesn't know yet. Unlike
// GetSession, it takes no callerUserID: resolving "who is this session
// for" is exactly the question being answered, not one the caller can
// supply in advance.
//
// entity.ErrSessionRevoked and entity.ErrSessionExpired are kept distinct
// from each other and from entity.ErrNotFound so a caller that legitimately
// needs the difference has it; collapsing them into one generic response
// is that future caller's job (see security.PasswordService.Verify's doc
// comment for the same division of responsibility).
func (s *SessionService) ValidateSession(ctx context.Context, sessionID string) (*entity.Session, error) {
	session, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.RevokedAt != nil {
		return nil, entity.ErrSessionRevoked
	}
	if !session.ExpiresAt.After(time.Now()) {
		// Lazy expiration: the row is only actually marked revoked once
		// something notices it's past due, rather than a background sweep
		// this milestone deliberately doesn't add. Best-effort: a failure
		// to persist this housekeeping write must not change the answer
		// ValidateSession already knows is correct.
		if expireErr := s.ExpireSession(ctx, sessionID); expireErr != nil {
			logging.FromContext(ctx).Error("failed to persist session expiry", zap.Error(expireErr))
		}
		return nil, entity.ErrSessionExpired
	}
	return session, nil
}

// RevokeSession revokes callerUserID's own session. Revoking an
// already-revoked session is a no-op, not an error — see
// repository.SessionRepository.Revoke's own "WHERE revoked_at IS NULL"
// clause, which is what makes the underlying UPDATE safe to repeat. A
// session belonging to a different user is reported as
// entity.ErrNotFound, the same collapse GetSession applies.
func (s *SessionService) RevokeSession(ctx context.Context, callerUserID, sessionID string, reason entity.RevocationReason) error {
	session, err := s.sessions.GetByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session.UserID != callerUserID {
		return entity.ErrNotFound
	}
	if session.RevokedAt != nil {
		return nil
	}

	if err := s.sessions.Revoke(ctx, sessionID, reason); err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			// Lost a race with a concurrent revoke between the read above
			// and this call. The row is now exactly what was asked for
			// (revoked), so this is success, not a failure to report.
			return nil
		}
		return err
	}
	logging.FromContext(ctx).Info("session revoked", zap.String("user_id", callerUserID), zap.String("reason", string(reason)))
	return nil
}

// ExpireSession marks a session revoked with entity.RevocationExpired,
// idempotently: an already-revoked or nonexistent session is treated as
// success, since "not currently an active, un-expired session" is exactly
// the end state being asked for either way. It takes no callerUserID —
// unlike RevokeSession, its caller is expected to be system-initiated
// housekeeping (see ValidateSession above), not a user acting on their own
// session.
func (s *SessionService) ExpireSession(ctx context.Context, sessionID string) error {
	err := s.sessions.Revoke(ctx, sessionID, entity.RevocationExpired)
	if errors.Is(err, entity.ErrNotFound) {
		return nil
	}
	return err
}
