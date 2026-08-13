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

// RefreshTokenServiceDeps wires RefreshTokenService to the abstractions
// Milestone 5B is explicitly built to reuse rather than duplicate:
// *SessionService (session validation/revocation, from Milestone 4B) and
// *security.TokenService (access-token minting, from Milestone 5A).
// AuthService.RefreshToken already does a version of this rotation using
// the old util.JWTSigner and no session-state check at all — it is left
// untouched (see this type's own doc comment) rather than migrated, since
// that is a bigger, separate change than "implement refresh-token
// creation, storage, rotation, validation, and refresh flow."
type RefreshTokenServiceDeps struct {
	RefreshTokens repository.RefreshTokenRepository
	Sessions      *SessionService
	Tokens        *security.TokenService
	// AccessTokenAudience is the `aud` claim every access token minted by
	// Refresh carries — see config.AccessTokenConfig.DefaultAudience's doc
	// comment: never a value a client can choose.
	AccessTokenAudience string
	// AccessTokenTTL is only used to report ExpiresIn accurately;
	// security.TokenService.CreateAccessToken doesn't return the
	// expiry it minted, so this is tracked alongside it rather than
	// widening that method's return signature for one caller's
	// convenience.
	AccessTokenTTL time.Duration
	// RefreshTTL is every newly-rotated refresh token's lifetime — see
	// config.RefreshTokenConfig's doc comment. Never client-configurable:
	// POST /auth/refresh's request body carries only refresh_token.
	RefreshTTL time.Duration
	// AuditTx records the audit_logs half of a refresh attempt — the same
	// AuditTxFunc type AuthServiceDeps already declares (see
	// auth_service.go): reused here verbatim, not redefined, since it's
	// the identical single-repository transactional pattern for the
	// identical reason (the hash-chain lock only serializes inside a real
	// transaction). A nil AuditTx skips audit-logging for refresh
	// entirely, which tests that don't care about it rely on.
	AuditTx AuditTxFunc
	// AbuseProtection is the Redis-backed refresh-abuse pre-check and
	// outcome recorder (Milestone 6C) — required, not optional; see
	// AuthServiceDeps.AbuseProtection's doc comment for the same "existing
	// tests supply a fake that allows everything" convention. Refresh's
	// policy is IP-only (never an account/pair dimension): a refresh token
	// is already a high-entropy secret, not a guessable credential, and
	// no account identifier exists until the token resolves anyway. This
	// complements RefreshTokenService's own existing reuse detection
	// (RevokeFamily/RevokeSession below) — it never replaces or duplicates
	// it; reuse detection is still what decides *whether this specific
	// token* is compromised, this only decides *whether this IP may keep
	// trying*.
	AbuseProtection ratelimit.AuthAbuseProtection
	// RateLimitRetryAfter is the fixed value RateLimitedError carries —
	// see that type's own doc comment (auth_service.go).
	RateLimitRetryAfter time.Duration
}

type RefreshTokenService struct {
	deps RefreshTokenServiceDeps
}

func NewRefreshTokenService(deps RefreshTokenServiceDeps) *RefreshTokenService {
	return &RefreshTokenService{deps: deps}
}

// RefreshResult is what a successful refresh hands back to the HTTP
// layer — a new access token and a new refresh token, per requirement
// #12's rotation diagram. It is its own type rather than a reuse of
// AuthService's LoginResult: the two operations are conceptually
// distinct (this one never touches a password or creates a session) even
// though their wire shape happens to match dto.TokenResponse identically.
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	SessionID    string
}

// Refresh implements POST /auth/refresh's entire flow: validate the
// presented refresh token, detect reuse, validate its session, rotate it,
// and mint a new access token. Every exit path — success or failure —
// writes exactly one best-effort audit_logs row via the deferred call
// below, the same "never invisible to an investigation just because it
// returned early" guarantee AuthService.Login's login_history write makes.
//
// "Nonexistent," "malformed" (caught by dto.RefreshRequest.Validate
// before this is ever called), "expired," "revoked," and "session no
// longer valid" all collapse to the exact same entity.ErrTokenExpired a
// caller sees — the identical anti-enumeration choice
// AuthService.RefreshToken already makes today, preserved here rather
// than reinvented, per requirement #19. The specific reason is still
// recorded internally, in the audit entry's Metadata (never the token or
// its hash) and in a log line.
func (s *RefreshTokenService) Refresh(ctx context.Context, rawToken string, meta LoginMeta) (*RefreshResult, error) {
	// Redis pre-check — IP-only, before the GetByTokenHash lookup, per
	// Milestone 6C's approved design. Check never returns an error to
	// interpret; see AuthService.Login's identical pre-check for the same
	// reasoning.
	rateLimitDims := ratelimit.Dimensions{IP: meta.IPAddress}
	if decision, _ := s.deps.AbuseProtection.Check(ctx, ratelimit.OperationRefresh, rateLimitDims); !decision.Allowed {
		return nil, RateLimitedError{RetryAfter: s.deps.RateLimitRetryAfter}
	}

	var current *entity.RefreshToken
	var refreshErr error
	var failureReason string
	defer func() {
		s.recordRefreshAudit(ctx, current, refreshErr, failureReason, meta)
	}()

	current, err := s.deps.RefreshTokens.GetByTokenHash(ctx, util.HashToken(rawToken))
	if errors.Is(err, entity.ErrNotFound) {
		failureReason = "not_found"
		refreshErr = entity.ErrTokenExpired
		s.recordRefreshFailure(ctx, rateLimitDims, meta)
		return nil, refreshErr
	}
	if err != nil {
		refreshErr = err
		return nil, refreshErr
	}

	if current.AlreadyRotated() {
		// Requirement #13/#15: a previously rotated token being presented
		// again is treated as compromise, not merely "invalid" — revoke
		// the whole family (no further refresh is possible on this chain)
		// and the session itself (so a future access-token-validating
		// caller sees it as dead too), then reject exactly like any other
		// failure. This reuse-detection logic is unchanged from Milestone
		// 5B — the abuse-protection call below only adds volume-based IP
		// throttling on top of it, never replacing or duplicating it.
		if err := s.deps.RefreshTokens.RevokeFamily(ctx, current.FamilyID, entity.RevocationReuseDetected); err != nil {
			logging.FromContext(ctx).Error("failed to revoke token family after reuse detection", zap.Error(err))
		}
		if err := s.deps.Sessions.RevokeSession(ctx, current.UserID, current.SessionID, entity.RevocationReuseDetected); err != nil {
			logging.FromContext(ctx).Error("failed to revoke session after reuse detection", zap.Error(err))
		}
		recordReuseDetectionRevocation(ctx, s.deps.AuditTx, current.UserID, current.SessionID, current.FamilyID, meta.IPAddress)
		logging.FromContext(ctx).Warn("refresh token reuse detected — session family revoked",
			zap.String("user_id", current.UserID), zap.String("family_id", current.FamilyID))
		failureReason = "reuse_detected"
		refreshErr = entity.ErrTokenReuseDetected
		s.recordRefreshFailure(ctx, rateLimitDims, meta)
		return nil, refreshErr
	}

	now := time.Now()
	if current.RevokedAt != nil || current.IsExpired(now) {
		failureReason = "token_revoked_or_expired"
		refreshErr = entity.ErrTokenExpired
		s.recordRefreshFailure(ctx, rateLimitDims, meta)
		return nil, refreshErr
	}

	// Requirement #10/#18: session lifetime takes precedence over the
	// refresh token's own expiry — a token that's individually still
	// valid must still be rejected if its session no longer is.
	if _, err := s.deps.Sessions.ValidateSession(ctx, current.SessionID); err != nil {
		logging.FromContext(ctx).Warn("refresh rejected: associated session is not valid",
			zap.String("user_id", current.UserID), zap.Error(err))
		failureReason = "session_invalid"
		refreshErr = entity.ErrTokenExpired
		s.recordRefreshFailure(ctx, rateLimitDims, meta)
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
	// Rotate is the one step that must be atomic — see
	// postgres.refreshTokenRepository.Rotate's own doc comment — and it
	// already is, reused as-is: insert next and revoke current inside one
	// transaction, with current's UPDATE guarded by
	// "WHERE revoked_at IS NULL" so two concurrent Refresh calls for the
	// same token can never both succeed.
	if err := s.deps.RefreshTokens.Rotate(ctx, current, next); err != nil {
		failureReason = "rotation_failed"
		refreshErr = err
		return nil, refreshErr
	}

	// Best-effort, deliberately outside Rotate's transaction — a failure
	// to record recent activity must never mask a successful rotation.
	if err := s.deps.Sessions.Touch(ctx, current.SessionID); err != nil {
		logging.FromContext(ctx).Error("failed to touch session after refresh", zap.Error(err))
	}

	accessToken, err := s.deps.Tokens.CreateAccessToken(current.UserID, s.deps.AccessTokenAudience, current.SessionID)
	if err != nil {
		refreshErr = err
		return nil, refreshErr
	}

	logging.FromContext(ctx).Info("access token refreshed", zap.String("user_id", current.UserID))
	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: nextRaw,
		ExpiresIn:    int(s.deps.AccessTokenTTL.Seconds()),
		SessionID:    current.SessionID,
	}, nil
}

// recordRefreshAudit best-effort appends one audit_logs row per refresh
// attempt — Action "auth.token_refresh", Result varying, Metadata
// carrying only a failure reason string (never the token, its hash, or
// current/next's TokenHash field) on failure. Like AuthService's
// recordLoginAudit, a failure here is logged and swallowed, never
// surfaced to the caller.
func (s *RefreshTokenService) recordRefreshAudit(ctx context.Context, current *entity.RefreshToken, refreshErr error, failureReason string, meta LoginMeta) {
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

// recordRefreshFailure best-effort records this invalid/expired/revoked/
// replayed refresh attempt in the abuse-protection layer and, only the
// moment the IP dimension newly crosses its threshold, writes one bounded
// auth.refresh_abuse_detected audit_logs event — distinct from
// recordRefreshAudit's own per-attempt "auth.token_refresh" entry above:
// that one is a per-token record of what happened to this specific
// token; this one is a volume signal about this IP, and only fires once
// per block episode, not once per attempt.
func (s *RefreshTokenService) recordRefreshFailure(ctx context.Context, dims ratelimit.Dimensions, meta LoginMeta) {
	blocked, err := s.deps.AbuseProtection.RecordFailure(ctx, ratelimit.OperationRefresh, dims)
	if err != nil {
		logging.FromContext(ctx).Error("failed to record refresh failure in abuse-protection layer", zap.Error(err))
		return
	}
	if !blocked {
		return
	}
	logging.FromContext(ctx).Warn("refresh-token abuse rate limit exceeded", zap.String("operation", ratelimit.OperationRefresh))
	if s.deps.AuditTx == nil {
		return
	}
	audit := &entity.AuditLogEntry{
		ActorType: entity.AuditActorSystem,
		Action:    "auth.refresh_abuse_detected",
		Result:    entity.AuditResultDenied,
		IPAddress: strPtr(meta.IPAddress),
		RequestID: strPtr(util.RequestIDFromContext(ctx)),
	}
	if err := s.deps.AuditTx(ctx, func(repo repository.AuditLogRepository) error {
		return repo.Append(ctx, audit)
	}); err != nil {
		logging.FromContext(ctx).Error("failed to record refresh-abuse audit event", zap.Error(err))
	}
}
