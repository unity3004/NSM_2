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
	"github.com/acme/auth-service/internal/ratelimit"
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

// RateLimitedError carries the fixed, configured Retry-After value the
// handler puts on the 429 response — never a value derived from which
// dimension actually blocked the request or how much of its window
// remains (Milestone 6C: exposing that would itself leak internal state).
type RateLimitedError struct{ RetryAfter time.Duration }

func (e RateLimitedError) Error() string { return "too many authentication attempts" }
func (e RateLimitedError) Unwrap() error { return entity.ErrRateLimited }

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
	// AbuseProtection is the Redis-backed brute-force/credential-stuffing
	// pre-check and outcome recorder (Milestone 6C) — required, not
	// optional: every existing test that constructs AuthServiceDeps now
	// supplies a ratelimit.FakeAuthAbuseProtection that allows everything
	// by default, so tests that don't care about rate limiting are
	// unaffected. See ratelimit.AuthAbuseProtection's own doc comment for
	// the exact division of responsibility between this dependency and
	// Login's own existing PostgreSQL-backed lockout, which is completely
	// unchanged by this milestone — this is a new, additional layer in
	// front of it, never a replacement.
	AbuseProtection ratelimit.AuthAbuseProtection
	// RateLimitRetryAfter is the fixed value RateLimitedError carries —
	// see that type's own doc comment on why it's fixed rather than
	// derived from internal rate-limit state.
	RateLimitRetryAfter time.Duration
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

	// Redis pre-check — before any PostgreSQL work or Argon2id
	// verification, per Milestone 6C's approved architecture. A blocked
	// pre-check never gets far enough to be "an evaluated login attempt"
	// in login_history's existing sense (no user lookup happened at all),
	// so no login_history row is written for it; the bounded,
	// transition-only auth.rate_limited audit event (written inside
	// RecordFailure's caller, not here) is where this is recorded
	// instead. Check never returns an error to interpret — Redis-failure
	// handling is entirely internal to it, resolved per the configured
	// fail_closed posture; see ratelimit.AuthAbuseProtection's doc
	// comment.
	rateLimitDims := ratelimit.Dimensions{IP: meta.IPAddress, Account: email}
	if decision, _ := s.deps.AbuseProtection.Check(ctx, ratelimit.OperationLogin, rateLimitDims); !decision.Allowed {
		return nil, RateLimitedError{RetryAfter: s.deps.RateLimitRetryAfter}
	}

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
		s.recordLoginFailure(ctx, rateLimitDims, meta)
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
		s.recordLoginFailure(ctx, rateLimitDims, meta)
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
		// Redis-side outcome recording — independent of, and in addition
		// to, the existing PostgreSQL IncrementFailedLoginAttempts/Lock
		// calls just below: two separate, deliberately non-duplicative
		// layers (see AuthServiceDeps.AbuseProtection's doc comment).
		s.recordLoginFailure(ctx, rateLimitDims, meta)

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
	// Resets the account and pair dimensions only, never IP — see
	// AuthAbuseProtection.RecordSuccess's own doc comment. Best-effort: a
	// Redis problem here must not change a login that has already
	// succeeded.
	if err := s.deps.AbuseProtection.RecordSuccess(ctx, ratelimit.OperationLogin, rateLimitDims); err != nil {
		logging.FromContext(ctx).Error("failed to reset abuse-protection counters after successful login", zap.Error(err))
	}

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
		RequestID:      strPtr(util.RequestIDFromContext(ctx)),
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

// recordLoginFailure best-effort records a failed login attempt in the
// abuse-protection layer and, only the moment a dimension newly crosses
// its threshold, writes one bounded audit_logs event — never one per
// repeated attempt against a dimension that's already blocked, which is
// what keeps this safe against an attacker who keeps hammering an
// already-blocked account or IP. A Redis problem here is logged and
// swallowed: by this point the actual login outcome has already been
// decided, and a bookkeeping failure must not change it (Milestone 6C's
// explicit outcome-recording-is-always-best-effort rule).
func (s *AuthService) recordLoginFailure(ctx context.Context, dims ratelimit.Dimensions, meta LoginMeta) {
	blocked, err := s.deps.AbuseProtection.RecordFailure(ctx, ratelimit.OperationLogin, dims)
	if err != nil {
		logging.FromContext(ctx).Error("failed to record login failure in abuse-protection layer", zap.Error(err))
		return
	}
	if blocked {
		logging.FromContext(ctx).Warn("authentication rate limit exceeded", zap.String("operation", ratelimit.OperationLogin))
		s.recordRateLimitAudit(ctx, ratelimit.OperationLogin, meta)
	}
}

// recordRateLimitAudit best-effort appends one audit_logs row for a
// rate-limit block transition — Action "auth.rate_limited", the existing
// lowercase-dot action-naming convention this codebase already uses
// throughout (user.login, auth.token_refresh, auth.logout), never the
// identifier that tripped the threshold, only IP metadata the same way
// every other audit write in this file already includes it.
func (s *AuthService) recordRateLimitAudit(ctx context.Context, operation string, meta LoginMeta) {
	if s.deps.AuditTx == nil {
		return
	}
	audit := &entity.AuditLogEntry{
		ActorType: entity.AuditActorSystem,
		Action:    "auth.rate_limited",
		Result:    entity.AuditResultDenied,
		IPAddress: strPtr(meta.IPAddress),
		RequestID: strPtr(util.RequestIDFromContext(ctx)),
		Metadata:  map[string]any{"operation": operation},
	}
	err := s.deps.AuditTx(ctx, func(repo repository.AuditLogRepository) error {
		return repo.Append(ctx, audit)
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record rate-limit audit event", zap.Error(err))
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
// Every exit path writes exactly one best-effort audit_logs row via the
// deferred call below — the same guarantee Login, Logout, and
// RefreshTokenService.Refresh's own "auth.token_refresh" audit write
// already make; this method previously made no such write at all.
func (s *AuthService) RefreshToken(ctx context.Context, rawToken string, meta LoginMeta) (*LoginResult, error) {
	var current *entity.RefreshToken
	var refreshErr error
	var failureReason string
	defer func() {
		s.recordRefreshAudit(ctx, current, refreshErr, failureReason, meta)
	}()

	var err error
	current, err = s.deps.RefreshTokens.GetByTokenHash(ctx, util.HashToken(rawToken))
	if errors.Is(err, entity.ErrNotFound) {
		failureReason = "not_found"
		refreshErr = entity.ErrTokenExpired
		return nil, refreshErr
	}
	if err != nil {
		refreshErr = err
		return nil, refreshErr
	}

	if current.AlreadyRotated() {
		_ = s.deps.RefreshTokens.RevokeFamily(ctx, current.FamilyID, entity.RevocationReuseDetected)
		_ = s.deps.Sessions.Revoke(ctx, current.SessionID, entity.RevocationReuseDetected)
		recordReuseDetectionRevocation(ctx, s.deps.AuditTx, current.UserID, current.SessionID, current.FamilyID, meta.IPAddress)
		// Warn: this is the strongest signal this service produces that a
		// credential may have been stolen, not merely misused — worth its
		// own alert rule in whatever reads these JSON logs, distinct from
		// a generic 401 count. Still Warn rather than Error for the same
		// reason as the lockout log above: RevokeFamily/Revoke doing their
		// job on cue is the system working correctly, not failing.
		logging.FromContext(ctx).Warn("refresh token reuse detected — session family revoked",
			zap.String("user_id", current.UserID), zap.String("family_id", current.FamilyID), zap.String("session_id", current.SessionID))
		failureReason = "reuse_detected"
		refreshErr = entity.ErrTokenReuseDetected
		return nil, refreshErr
	}
	now := time.Now()
	if current.RevokedAt != nil || current.IsExpired(now) {
		failureReason = "token_revoked_or_expired"
		refreshErr = entity.ErrTokenExpired
		return nil, refreshErr
	}

	// Session lifetime takes precedence over the refresh token's own
	// expiry — a token that is individually still valid must still be
	// rejected once its session is not, the same rule
	// RefreshTokenService.Refresh already enforces via
	// SessionService.ValidateSession (see that method's identical check).
	// Without this, UserService.DisableUser's session revocation
	// (RevokeAllForUser) would have no actual effect on this legacy
	// refresh path: a disabled user's already-issued refresh token could
	// keep minting new access tokens indefinitely, since nothing here
	// previously looked at session state at all — confirmed for real by
	// TestUserManagement_FullLifecycle before this check was added.
	session, err := s.deps.Sessions.GetByID(ctx, current.SessionID)
	if err != nil {
		failureReason = "session_not_found"
		refreshErr = entity.ErrTokenExpired
		return nil, refreshErr
	}
	if session.RevokedAt != nil || !session.ExpiresAt.After(now) {
		failureReason = "session_invalid"
		refreshErr = entity.ErrTokenExpired
		return nil, refreshErr
	}

	nextRaw, err := util.NewOpaqueToken()
	if err != nil {
		refreshErr = err
		return nil, refreshErr
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
		if errors.Is(err, entity.ErrNotFound) {
			// The guarded UPDATE (WHERE revoked_at IS NULL) affected zero
			// rows: a different concurrent goroutine already rotated or
			// revoked this exact token between this call's own lookup and
			// this Rotate attempt — a losing concurrent refresh, not a
			// resource that was ever missing. See
			// RefreshTokenService.Refresh's identical fix and its own doc
			// comment for the full explanation; this is the legacy
			// refresh flow's copy of the same bug.
			failureReason = "rotation_lost_race"
			refreshErr = entity.ErrTokenExpired
			return nil, refreshErr
		}
		failureReason = "rotation_failed"
		refreshErr = err
		return nil, refreshErr
	}
	_ = s.deps.Sessions.Touch(ctx, current.SessionID, now)

	user, err := s.deps.Users.GetByID(ctx, current.UserID)
	if err != nil {
		refreshErr = err
		return nil, refreshErr
	}
	accessToken, expiresAt, err := s.deps.Tokens.Sign(user.ID, user.OrganizationID, current.SessionID, nil)
	if err != nil {
		refreshErr = err
		return nil, refreshErr
	}

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: nextRaw,
		ExpiresIn:    int(time.Until(expiresAt).Seconds()),
		SessionID:    current.SessionID,
	}, nil
}

// recordRefreshAudit best-effort appends one audit_logs row per
// refresh attempt — Action "auth.token_refresh", the same action name
// RefreshTokenService.recordRefreshAudit already uses for the Milestone 5B
// flow, so the two refresh paths' audit trails are never distinguishable
// by action name alone. A failure here is logged and swallowed, never
// surfaced to the caller, the same convention every other audit write in
// this file already follows.
func (s *AuthService) recordRefreshAudit(ctx context.Context, current *entity.RefreshToken, refreshErr error, failureReason string, meta LoginMeta) {
	if s.deps.AuditTx == nil {
		return
	}

	result := entity.AuditResultSuccess
	metadata := map[string]any{}
	if refreshErr != nil {
		result = entity.AuditResultFailure
		metadata["failure_reason"] = failureReason
	}

	var actorID, resourceID *string
	if current != nil {
		actorID = &current.UserID
		resourceID = &current.SessionID
	}

	audit := &entity.AuditLogEntry{
		ActorType:    entity.AuditActorUser,
		ActorID:      actorID,
		Action:       "auth.token_refresh",
		ResourceType: strPtr("session"),
		ResourceID:   resourceID,
		Result:       result,
		IPAddress:    strPtr(meta.IPAddress),
		RequestID:    strPtr(util.RequestIDFromContext(ctx)),
		Metadata:     metadata,
	}
	err := s.deps.AuditTx(ctx, func(repo repository.AuditLogRepository) error {
		return repo.Append(ctx, audit)
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record refresh audit event", zap.Error(err))
	}
}

// Logout implements POST /auth/logout: revoke the session and, if the
// client still holds it, the refresh-token family riding alongside it.
// Every exit path writes exactly one best-effort audit_logs row via the
// deferred call below — the same "never invisible to an investigation just
// because it returned early" guarantee Login's login_history write and
// RefreshTokenService.Refresh's own audit write already make; this method
// previously made no such write at all.
func (s *AuthService) Logout(ctx context.Context, organizationID, userID, sessionID string, rawRefreshToken *string, meta LoginMeta) error {
	var logoutErr error
	defer func() {
		s.recordLogoutAudit(ctx, organizationID, userID, sessionID, logoutErr, meta)
	}()

	if rawRefreshToken != nil {
		if rt, err := s.deps.RefreshTokens.GetByTokenHash(ctx, util.HashToken(*rawRefreshToken)); err == nil {
			_ = s.deps.RefreshTokens.RevokeFamily(ctx, rt.FamilyID, entity.RevocationLogout)
		}
	}
	if err := s.deps.Sessions.Revoke(ctx, sessionID, entity.RevocationLogout); err != nil {
		logoutErr = err
		return logoutErr
	}
	logging.FromContext(ctx).Info("logout", zap.String("session_id", sessionID))
	return nil
}

// recordLogoutAudit best-effort appends one audit_logs row per logout
// attempt — Action "auth.logout", the same action name
// LogoutService.recordLogoutAudit already uses for the Milestone 6B flow,
// so the two logout paths' audit trails are never distinguishable by
// action name alone. logoutFailureReason is shared with that method
// (defined once, in logout_service.go, in this same package) rather than
// duplicated. A failure here is logged and swallowed, never surfaced to
// the caller, the same convention every other audit write in this file
// already follows.
func (s *AuthService) recordLogoutAudit(ctx context.Context, organizationID, userID, sessionID string, logoutErr error, meta LoginMeta) {
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
		OrganizationID: strPtr(organizationID),
		ActorType:      entity.AuditActorUser,
		ActorID:        actorID,
		Action:         "auth.logout",
		ResourceType:   strPtr("session"),
		ResourceID:     resourceID,
		Result:         result,
		IPAddress:      strPtr(meta.IPAddress),
		RequestID:      strPtr(util.RequestIDFromContext(ctx)),
		Metadata:       metadata,
	}
	err := s.deps.AuditTx(ctx, func(repo repository.AuditLogRepository) error {
		return repo.Append(ctx, audit)
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record logout audit event", zap.Error(err))
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
