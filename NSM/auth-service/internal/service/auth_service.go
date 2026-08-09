// Package service holds use cases — the application's actual business
// rules. Every type here depends only on internal/repository interfaces
// and internal/entity, never on net/http or database/sql: that's what
// makes AuthService_test.go (see the colocated test) able to run against a
// hand-written fake repository with no database at all, and what would let
// a future gRPC or CLI delivery mechanism reuse this exact logic untouched.
package service

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
)

const (
	maxFailedLoginAttempts = 5
	lockoutDuration        = 15 * time.Minute
)

// AccountLockedError carries the unlock time so the handler can tell the
// caller when to retry, without the service layer depending on any HTTP
// concept to do it.
type AccountLockedError struct{ Until time.Time }

func (e AccountLockedError) Error() string { return "account is locked" }
func (e AccountLockedError) Unwrap() error { return entity.ErrAccountLocked }

// LoginMeta is the request metadata that doesn't belong in dto.LoginRequest
// (it's read from headers/connection info, not the JSON body) but that
// login_history needs recorded regardless of outcome.
type LoginMeta struct {
	IPAddress string
	UserAgent string
}

// AuditTxFunc appends one audit_logs row inside its own transaction — the
// single-repository sibling of RegistrationTxFunc (see user_service.go).
// It exists even for a single Append because
// postgres.auditLogRepository.Append's hash-chain concurrency guarantee
// (pg_advisory_xact_lock) only serializes concurrent appends to the same
// organization when it runs inside a real transaction; handing Login a
// bare *sql.DB-backed repository instead would silently reintroduce a
// hash-chain race between two concurrent logins.
type AuditTxFunc func(ctx context.Context, fn func(repository.AuditLogRepository) error) error

type AuthServiceDeps struct {
	Users         repository.UserRepository
	Sessions      repository.SessionRepository
	RefreshTokens repository.RefreshTokenRepository
	LoginHistory  repository.LoginHistoryRepository
	Tokens        *util.JWTSigner
	// Passwords verifies a login attempt's plaintext against the stored
	// Argon2id hash — see internal/security.PasswordService. It is the
	// same instance UserService uses to create that hash in the first
	// place, so Hash and Verify are always talking about the same
	// algorithm and parameters.
	Passwords  *security.PasswordService
	RefreshTTL time.Duration
	// AuditTx records the audit_logs half of a login attempt — see
	// AuditTxFunc. A nil AuditTx skips audit-logging for login entirely,
	// which existing tests that don't care about it rely on.
	AuditTx AuditTxFunc
}

type AuthService struct {
	deps AuthServiceDeps
}

func NewAuthService(deps AuthServiceDeps) *AuthService {
	return &AuthService{deps: deps}
}

// LoginResult is what a successful login hands back to the HTTP layer —
// raw secrets included, since minting them is this method's entire job.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	SessionID    string
}

// Login implements POST /auth/login. It always writes exactly one
// login_history row, on every exit path — see the deferred record below —
// so a failure can never be invisible to brute-force detection just
// because it returned early.
func (s *AuthService) Login(ctx context.Context, organizationID string, email, password string, meta LoginMeta) (*LoginResult, error) {
	// Normalized the same way Register normalizes before its own
	// uniqueness check (see UserService.Register / util.NormalizeEmail) —
	// a login for "Marcus.Webb@ACME.com " must find the same row a
	// registration for "marcus.webb@acme.com" created.
	email = util.NormalizeEmail(email)

	now := time.Now()
	entry := &entity.LoginHistoryEntry{
		OrganizationID:      &organizationID,
		AttemptedIdentifier: &email,
		AuthMethod:          entity.AuthMethodPassword,
		IPAddress:           strPtr(meta.IPAddress),
	}
	var loginErr error
	defer func() {
		_ = s.deps.LoginHistory.Record(ctx, entry) // best-effort: never blocks or masks loginErr
		s.recordLoginAudit(ctx, organizationID, entry, meta)
	}()

	user, err := s.deps.Users.GetByEmail(ctx, organizationID, email)
	if errors.Is(err, entity.ErrNotFound) {
		entry.Status = entity.LoginFailureUnknownIdentity
		loginErr = entity.ErrInvalidCredentials
		return nil, loginErr
	}
	if err != nil {
		// A genuine lookup failure (database unavailable, etc.) — distinct
		// from "no such user" above, and must stay distinct internally even
		// though writeServiceError's default branch already keeps the
		// external response equally generic either way.
		entry.Status = entity.LoginFailureOther
		loginErr = err
		return nil, loginErr
	}
	entry.UserID = &user.ID

	if user.Status == entity.UserStatusDisabled {
		entry.Status = entity.LoginFailureDisabled
		loginErr = entity.ErrAccountDisabled
		return nil, loginErr
	}
	if user.IsLocked(now) {
		entry.Status = entity.LoginFailureLocked
		loginErr = AccountLockedError{Until: *user.LockedUntil}
		return nil, loginErr
	}

	passwordOK := false
	if user.PasswordHash != nil {
		var verifyErr error
		passwordOK, verifyErr = s.deps.Passwords.Verify(password, *user.PasswordHash)
		if verifyErr != nil {
			// A malformed stored hash is a data-integrity problem, not a
			// wrong-password event — worth its own Error log distinct
			// from the Debug/Warn below — but it must still fail the
			// login the same generic way (entity.ErrInvalidCredentials),
			// exactly like an unset PasswordHash (SSO-only account) does.
			// Verify's own doc comment is explicit that collapsing this
			// distinction into one outcome is the caller's job, not
			// PasswordService's.
			logging.FromContext(ctx).Error("stored password hash failed to parse",
				zap.String("user_id", user.ID), zap.Error(verifyErr))
			passwordOK = false
		}
	}
	if !passwordOK {
		attempts, incErr := s.deps.Users.IncrementFailedLoginAttempts(ctx, user.ID)
		if incErr == nil && attempts >= maxFailedLoginAttempts {
			until := now.Add(lockoutDuration)
			_ = s.deps.Users.Lock(ctx, user.ID, until)
			entry.Status = entity.LoginFailureLocked
			loginErr = AccountLockedError{Until: until}
			// Warn, not Error: the code did exactly what it should — this
			// is a business/security event a human may want to look at
			// (is this the account owner mistyping a password, or
			// credential stuffing?), not a defect in the service. See
			// RefreshToken's reuse-detection log below for the same
			// classification call made the same way.
			logging.FromContext(ctx).Warn("account locked after repeated failed logins",
				zap.String("user_id", user.ID), zap.Int("attempts", attempts), zap.Time("locked_until", until))
			return nil, loginErr
		}
		entry.Status = entity.LoginFailureBadPassword
		loginErr = entity.ErrInvalidCredentials
		// Debug, not Warn: one wrong password is not yet a signal worth a
		// human's attention — it's the *rate* of them that matters, and
		// that's what the Warn above fires on. This line exists so a
		// support investigation ("did this specific login attempt even
		// reach us?") has something to grep for with debug logging
		// enabled, without that noise being on by default in production.
		logging.FromContext(ctx).Debug("failed login attempt",
			zap.String("user_id", user.ID), zap.Int("attempts", attempts))
		return nil, loginErr
	}

	_ = s.deps.Users.ResetFailedLoginAttempts(ctx, user.ID)

	session, result, err := s.issueSession(ctx, user, meta)
	if err != nil {
		loginErr = err
		return nil, loginErr
	}

	entry.Status = entity.LoginSuccess
	entry.SessionID = &session.ID
	logging.FromContext(ctx).Info("login succeeded",
		zap.String("user_id", user.ID), zap.String("session_id", session.ID))
	return result, nil
}

// recordLoginAudit best-effort appends one audit_logs row for this login
// attempt, derived from the already-populated login_history entry so the
// two records can never disagree about what happened. Like the
// LoginHistory.Record call beside it, a failure here is logged and
// swallowed, never surfaced to the caller: audit_logs is an observability
// record of an attempt against an already-durable user row, not a write
// anything else needs to be atomic with (contrast UserService.Register,
// where the audit write and the user INSERT it describes must commit or
// roll back together).
func (s *AuthService) recordLoginAudit(ctx context.Context, organizationID string, entry *entity.LoginHistoryEntry, meta LoginMeta) {
	if s.deps.AuditTx == nil {
		return
	}

	result := entity.AuditResultFailure
	metadata := map[string]any{}
	if entry.Status == entity.LoginSuccess {
		result = entity.AuditResultSuccess
	} else {
		metadata["failure_reason"] = string(entry.Status)
	}

	audit := &entity.AuditLogEntry{
		OrganizationID: &organizationID,
		ActorType:      entity.AuditActorUser,
		ActorID:        entry.UserID,
		Action:         "user.login",
		ResourceType:   strPtr("user"),
		ResourceID:     entry.UserID,
		Result:         result,
		IPAddress:      strPtr(meta.IPAddress),
		Metadata:       metadata,
	}
	err := s.deps.AuditTx(ctx, func(repo repository.AuditLogRepository) error {
		return repo.Append(ctx, audit)
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record login audit event",
			zap.String("organization_id", organizationID), zap.Error(err))
	}
}

// issueSession mints a session, its first refresh token, and a matching
// access token — the three artifacts every successful authentication
// produces, shared between Login and (in a fuller build) SSO callbacks.
func (s *AuthService) issueSession(ctx context.Context, user *entity.User, meta LoginMeta) (*entity.Session, *LoginResult, error) {
	sessionRaw, err := util.NewOpaqueToken()
	if err != nil {
		return nil, nil, err
	}
	session := &entity.Session{
		UserID:           user.ID,
		SessionTokenHash: util.HashToken(sessionRaw),
		IPAddress:        strPtr(meta.IPAddress),
		UserAgent:        strPtr(meta.UserAgent),
		ExpiresAt:        time.Now().Add(s.deps.RefreshTTL),
	}
	if err := s.deps.Sessions.Create(ctx, session); err != nil {
		return nil, nil, err
	}

	refreshRaw, err := util.NewOpaqueToken()
	if err != nil {
		return nil, nil, err
	}
	familyID := util.NewUUID()
	refreshToken := &entity.RefreshToken{
		SessionID: session.ID,
		UserID:    user.ID,
		TokenHash: util.HashToken(refreshRaw),
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(s.deps.RefreshTTL),
	}
	if err := s.deps.RefreshTokens.Create(ctx, refreshToken); err != nil {
		return nil, nil, err
	}

	// NOTE: Permissions is left empty here — resolving effective
	// permissions (direct user_roles + group-inherited group_roles) is
	// RBACService's job in the full build; this vertical slice stops at
	// "who is this," not "what may they do," to keep the demonstrated
	// slice to auth + users. See internal/repository/rbac.go and group.go
	// for the contracts that resolution would be built against.
	accessToken, expiresAt, err := s.deps.Tokens.Sign(user.ID, user.OrganizationID, session.ID, nil)
	if err != nil {
		return nil, nil, err
	}

	return session, &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshRaw,
		ExpiresIn:    int(time.Until(expiresAt).Seconds()),
		SessionID:    session.ID,
	}, nil
}

// RefreshToken implements POST /auth/token/refresh, including
// rotation-with-reuse-detection: see entity.RefreshToken's doc comment for
// what AlreadyRotated means and why it triggers a family-wide revocation.
func (s *AuthService) RefreshToken(ctx context.Context, rawToken string) (*LoginResult, error) {
	current, err := s.deps.RefreshTokens.GetByTokenHash(ctx, util.HashToken(rawToken))
	if errors.Is(err, entity.ErrNotFound) {
		return nil, entity.ErrTokenExpired
	}
	if err != nil {
		return nil, err
	}

	if current.AlreadyRotated() {
		_ = s.deps.RefreshTokens.RevokeFamily(ctx, current.FamilyID, entity.RevocationReuseDetected)
		_ = s.deps.Sessions.Revoke(ctx, current.SessionID, entity.RevocationReuseDetected)
		// Warn: this is the strongest signal this service produces that a
		// credential may have been stolen, not merely misused — worth its
		// own alert rule in whatever reads these JSON logs, distinct from
		// a generic 401 count. Still Warn rather than Error for the same
		// reason as the lockout log above: RevokeFamily/Revoke doing their
		// job on cue is the system working correctly, not failing.
		logging.FromContext(ctx).Warn("refresh token reuse detected — session family revoked",
			zap.String("user_id", current.UserID), zap.String("family_id", current.FamilyID), zap.String("session_id", current.SessionID))
		return nil, entity.ErrTokenReuseDetected
	}
	now := time.Now()
	if current.RevokedAt != nil || current.IsExpired(now) {
		return nil, entity.ErrTokenExpired
	}

	nextRaw, err := util.NewOpaqueToken()
	if err != nil {
		return nil, err
	}
	next := &entity.RefreshToken{
		SessionID:     current.SessionID,
		UserID:        current.UserID,
		TokenHash:     util.HashToken(nextRaw),
		FamilyID:      current.FamilyID,
		ParentTokenID: &current.ID,
		ExpiresAt:     now.Add(s.deps.RefreshTTL),
	}
	if err := s.deps.RefreshTokens.Rotate(ctx, current, next); err != nil {
		return nil, err
	}
	_ = s.deps.Sessions.Touch(ctx, current.SessionID, now)

	user, err := s.deps.Users.GetByID(ctx, current.UserID)
	if err != nil {
		return nil, err
	}
	accessToken, expiresAt, err := s.deps.Tokens.Sign(user.ID, user.OrganizationID, current.SessionID, nil)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: nextRaw,
		ExpiresIn:    int(time.Until(expiresAt).Seconds()),
		SessionID:    current.SessionID,
	}, nil
}

// Logout implements POST /auth/logout: revoke the session and, if the
// client still holds it, the refresh-token family riding alongside it.
func (s *AuthService) Logout(ctx context.Context, sessionID string, rawRefreshToken *string) error {
	if rawRefreshToken != nil {
		if rt, err := s.deps.RefreshTokens.GetByTokenHash(ctx, util.HashToken(*rawRefreshToken)); err == nil {
			_ = s.deps.RefreshTokens.RevokeFamily(ctx, rt.FamilyID, entity.RevocationLogout)
		}
	}
	if err := s.deps.Sessions.Revoke(ctx, sessionID, entity.RevocationLogout); err != nil {
		return err
	}
	logging.FromContext(ctx).Info("logout", zap.String("session_id", sessionID))
	return nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
