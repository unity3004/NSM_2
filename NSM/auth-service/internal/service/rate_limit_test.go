package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
)

// --- login: pre-check wiring ---

// TestLogin_RateLimited_IPThreshold proves AuthService.Login actually
// calls through to AbuseProtection.Check/RecordFailure — not just that
// the ratelimit package's own logic works (internal/ratelimit's own tests
// already prove that in isolation).
func TestLogin_RateLimited_IPThreshold(t *testing.T) {
	svc, users, _ := newTestAuthServiceWithAbuseProtection(t)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")

	// 20 failed attempts against 20 different, nonexistent accounts from
	// the same IP — enough to cross the IP threshold (20) without ever
	// touching the account/pair dimensions for "victim@example.com".
	for i := 0; i < 20; i++ {
		_, err := svc.Login(t.Context(), "org-1", "nobody-"+string(rune('a'+i))+"@example.com", "wrong-password", LoginMeta{IPAddress: "203.0.113.1"})
		if err == nil {
			t.Fatalf("attempt %d: Login() error = nil, want an error (unknown identity)", i)
		}
	}

	// The 21st attempt, even against a real account with the correct
	// password, must now be rejected by the pre-check before password
	// verification ever runs.
	_, err := svc.Login(t.Context(), "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.1"})
	var limited RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("Login() after crossing the IP threshold, error = %v, want RateLimitedError", err)
	}
	if limited.RetryAfter != 60*time.Second {
		t.Errorf("RetryAfter = %v, want the configured 60s", limited.RetryAfter)
	}
}

func TestLogin_RateLimited_AccountThreshold(t *testing.T) {
	svc, users, _ := newTestAuthServiceWithAbuseProtection(t)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")

	// 5 failed attempts against the same account from 5 different IPs —
	// credential-stuffing shape — enough to cross the account threshold.
	for i := 0; i < 5; i++ {
		_, err := svc.Login(t.Context(), "org-1", "victim@example.com", "wrong-password", LoginMeta{IPAddress: "203.0.113." + string(rune('1'+i))})
		if err == nil {
			t.Fatalf("attempt %d: Login() error = nil, want an error", i)
		}
	}

	_, err := svc.Login(t.Context(), "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "198.51.100.50"})
	var limited RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("Login() after crossing the account threshold, error = %v, want RateLimitedError", err)
	}
}

// TestLogin_RateLimitPreCheck_RunsBeforePasswordVerification proves the
// pre-check happens before Argon2id verification, not after: a correct
// password presented once the pre-check is already blocking must still
// be rejected as RateLimitedError, never entity.ErrInvalidCredentials or
// a successful login.
func TestLogin_RateLimitPreCheck_RunsBeforePasswordVerification(t *testing.T) {
	svc, users, abuseProtection := newTestAuthServiceWithAbuseProtection(t)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")

	// Directly drive the account dimension to its threshold without going
	// through Login at all, to isolate "the pre-check blocks" from "the
	// failure-recording path works" (proven separately above).
	dims := ratelimit.Dimensions{IP: "203.0.113.1", Account: "victim@example.com"}
	for i := 0; i < 5; i++ {
		if _, err := abuseProtection.RecordFailure(t.Context(), ratelimit.OperationLogin, dims); err != nil {
			t.Fatalf("RecordFailure(): %v", err)
		}
	}

	_, err := svc.Login(t.Context(), "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.1"})
	var limited RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("Login() with a correct password while blocked, error = %v, want RateLimitedError", err)
	}
}

// TestLogin_RateLimited_SuccessResetsAccountDimension proves
// AuthService.Login calls RecordSuccess on a successful login, not just
// that RecordSuccess itself works (proven at the ratelimit package level).
func TestLogin_RateLimited_SuccessResetsAccountDimension(t *testing.T) {
	svc, users, _ := newTestAuthServiceWithAbuseProtection(t)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")

	for i := 0; i < 4; i++ {
		if _, err := svc.Login(t.Context(), "org-1", "victim@example.com", "wrong-password", LoginMeta{IPAddress: "203.0.113.1"}); err == nil {
			t.Fatalf("attempt %d: Login() error = nil, want an error", i)
		}
	}

	if _, err := svc.Login(t.Context(), "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.1"}); err != nil {
		t.Fatalf("Login() with the correct password, error = %v, want nil", err)
	}

	// If the successful login had NOT reset the account counter, 4 more
	// failures would now be the 8th/9th against a limit of 5 and would
	// already be blocked. It must not be.
	for i := 0; i < 4; i++ {
		_, err := svc.Login(t.Context(), "org-1", "victim@example.com", "wrong-password", LoginMeta{IPAddress: "203.0.113.1"})
		var limited RateLimitedError
		if errors.As(err, &limited) {
			t.Fatalf("attempt %d: Login() = RateLimitedError, want entity.ErrInvalidCredentials — the account counter was not reset by the earlier success", i)
		}
		if err == nil {
			t.Fatalf("attempt %d: Login() error = nil, want an error", i)
		}
	}
}

// --- refresh: IP-only pre-check wiring ---

func TestRefresh_RateLimited_IPThreshold(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenServiceWithAbuseProtection(t)
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	for i := 0; i < 30; i++ {
		_, err := svc.Refresh(t.Context(), "not-a-real-token", LoginMeta{IPAddress: "203.0.113.1"})
		if err == nil {
			t.Fatalf("attempt %d: Refresh() error = nil, want an error", i)
		}
	}

	_, err := svc.Refresh(t.Context(), raw, LoginMeta{IPAddress: "203.0.113.1"})
	var limited RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("Refresh() with a genuinely valid token after crossing the IP threshold, error = %v, want RateLimitedError", err)
	}
}

// TestRefresh_RateLimited_ValidRefreshDoesNotIncrement proves a valid
// rotation never calls RecordFailure — driving 29 *valid* refreshes from
// the same IP (well under the limit of 30 failures, but this proves valid
// operations aren't counted as failures at all, not merely that they
// don't individually cross the threshold).
func TestRefresh_RateLimited_ValidRefreshDoesNotIncrement(t *testing.T) {
	svc, refreshTokens, sessionRepo, abuseProtection := newTestRefreshTokenServiceWithAbuseProtection(t)
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour))

	for i := 0; i < 29; i++ {
		result, err := svc.Refresh(t.Context(), raw, LoginMeta{IPAddress: "203.0.113.1"})
		if err != nil {
			t.Fatalf("attempt %d: Refresh() error = %v, want nil", i, err)
		}
		raw = result.RefreshToken
	}

	decision, err := abuseProtection.Check(t.Context(), ratelimit.OperationRefresh, ratelimit.Dimensions{IP: "203.0.113.1"})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !decision.Allowed {
		t.Error("29 valid refreshes incremented the failure counter enough to block — valid operations must not count as failures")
	}
}

// --- audit: bounded, transition-only rate-limit events ---

// TestLogin_RateLimited_WritesBoundedAuditEvent proves the auth.rate_limited
// audit event fires exactly once — on the block transition — not once per
// subsequent attempt against an already-blocked account.
func TestLogin_RateLimited_WritesBoundedAuditEvent(t *testing.T) {
	users := mocks.NewFakeUserRepository()
	sessions := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	loginHistory := mocks.NewFakeLoginHistoryRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
	abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationLogin: {
				Account: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 5, BlockDuration: 15 * time.Minute},
			},
		},
	})
	svc := NewAuthService(AuthServiceDeps{
		Users:               users,
		Sessions:            sessions,
		RefreshTokens:       refreshTokens,
		LoginHistory:        loginHistory,
		Tokens:              util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		Passwords:           security.NewPasswordService(testPasswordParams),
		RefreshTTL:          30 * 24 * time.Hour,
		AuditTx:             auditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: 60 * time.Second,
	})
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")

	for i := 0; i < 5; i++ {
		_, _ = svc.Login(t.Context(), "org-1", "victim@example.com", "wrong-password", LoginMeta{IPAddress: "203.0.113.1"})
	}
	// Repeatedly hitting the now-blocked account must not write another
	// rate-limit audit row each time.
	for i := 0; i < 5; i++ {
		_, _ = svc.Login(t.Context(), "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.1"})
	}

	rateLimitedEvents := 0
	for _, entry := range audit.Entries {
		if entry.Action == "auth.rate_limited" {
			rateLimitedEvents++
			if entry.Result != "denied" {
				t.Errorf("auth.rate_limited result = %q, want %q", entry.Result, "denied")
			}
		}
	}
	if rateLimitedEvents != 1 {
		t.Errorf("auth.rate_limited audit events = %d, want exactly 1 (bounded to the block transition)", rateLimitedEvents)
	}
}

// --- fault injection: abuse-protection outcome-recording failures ---
//
// AuthService.Login treats every AbuseProtection call according to the
// policy already implemented in auth_service.go: Check's own error is
// resolved internally per Config.FailClosed and never reaches Login as a
// Go error at all (see fake_limiter.go's FailNextCheck doc comment, which
// mirrors RedisAuthAbuseProtection.Check's real contract); RecordFailure
// and RecordSuccess are always best-effort, so their errors are logged
// and swallowed, never surfaced to the caller (recordLoginFailure's and
// Login's own doc comments). These tests prove that existing behavior
// continues to hold when the abuse-protection layer itself errors — they
// do not invent any new policy.

// newTestAuthServiceForFaultInjection is newTestAuthServiceWithAbuseProtection
// plus the two things these tests specifically need that the shared
// helper doesn't expose: an explicit FailClosed posture, and a logger
// (via context, the same way AuthService actually reads it — see
// logging.FromContext) the test can inspect with zaptest/observer.
func newTestAuthServiceForFaultInjection(t *testing.T, failClosed bool) (svc *AuthService, users *mocks.FakeUserRepository, abuseProtection *ratelimit.FakeAuthAbuseProtection, audit *mocks.FakeAuditLogRepository, ctx context.Context, logs *observer.ObservedLogs) {
	t.Helper()
	users = mocks.NewFakeUserRepository()
	sessions := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	loginHistory := mocks.NewFakeLoginHistoryRepository()
	audit = mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
	abuseProtection = ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		FailClosed: failClosed,
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationLogin: {
				Account: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 5, BlockDuration: 15 * time.Minute},
			},
		},
	})
	svc = NewAuthService(AuthServiceDeps{
		Users:               users,
		Sessions:            sessions,
		RefreshTokens:       refreshTokens,
		LoginHistory:        loginHistory,
		Tokens:              util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		Passwords:           security.NewPasswordService(testPasswordParams),
		RefreshTTL:          30 * 24 * time.Hour,
		AuditTx:             auditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: 60 * time.Second,
	})
	core, observedLogs := observer.New(zapcore.DebugLevel)
	logs = observedLogs
	ctx = logging.WithContext(t.Context(), zap.New(core))
	return svc, users, abuseProtection, audit, ctx, logs
}

// A: a Check failure follows the existing, already-configured
// fail-open/fail-closed posture — proven at both settings, not just one,
// since either without the other would leave the actual policy unproven.

func TestLogin_AbuseProtectionCheckFailure_FailClosed(t *testing.T) {
	svc, users, abuseProtection, _, ctx, _ := newTestAuthServiceForFaultInjection(t, true)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")
	abuseProtection.FailNextCheck = errors.New("redis: connection refused")

	_, err := svc.Login(ctx, "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.1"})
	var limited RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("Login() with Check failing and FailClosed=true, error = %v, want RateLimitedError", err)
	}
}

func TestLogin_AbuseProtectionCheckFailure_FailOpen(t *testing.T) {
	svc, users, abuseProtection, _, ctx, _ := newTestAuthServiceForFaultInjection(t, false)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")
	abuseProtection.FailNextCheck = errors.New("redis: connection refused")

	// A correct password must still succeed: FailClosed=false means a
	// Check that can't reach Redis resolves to "allowed", not "blocked".
	if _, err := svc.Login(ctx, "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.1"}); err != nil {
		t.Fatalf("Login() with Check failing and FailClosed=false, error = %v, want nil", err)
	}
}

// B, C, D, E: a RecordFailure failure must not panic, must not leak the
// underlying Redis error to the client, must leave the authentication
// response and the independent PostgreSQL lockout layer exactly as they
// already behave without any Redis problem, and the logging/audit
// footprint it leaves must stay bounded to the one existing Error log
// line — no auth.rate_limited audit event, since recordLoginFailure
// returns before ever checking the blocked flag once RecordFailure itself
// errors.
func TestLogin_RecordFailureError_BoundedAndNotLeaked(t *testing.T) {
	svc, users, abuseProtection, audit, ctx, logs := newTestAuthServiceForFaultInjection(t, false)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")
	injected := errors.New("redis: connection reset by peer")
	abuseProtection.FailNextRecordFailure = injected

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Login() panicked: %v", r) // B
			}
		}()
		_, err = svc.Login(ctx, "org-1", "victim@example.com", "wrong-password", LoginMeta{IPAddress: "203.0.113.1"})
	}()

	// C: the client-visible error is still the existing generic
	// entity.ErrInvalidCredentials — never the injected error, and never a
	// string containing it.
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want entity.ErrInvalidCredentials", err)
	}
	if strings.Contains(err.Error(), injected.Error()) {
		t.Fatalf("Login() error = %q leaks the underlying abuse-protection error %q", err.Error(), injected.Error())
	}

	// D: the independent PostgreSQL lockout layer must be unaffected by
	// the Redis-layer failure — it still sees this as attempt 1, exactly
	// as it would if RecordFailure had not errored at all.
	stored, getErr := users.GetByEmail(ctx, "org-1", "victim@example.com")
	if getErr != nil {
		t.Fatalf("GetByEmail(): %v", getErr)
	}
	if stored.FailedLoginAttempts != 1 {
		t.Errorf("FailedLoginAttempts = %d, want 1 — the Postgres lockout layer must be unaffected by the Redis-layer failure", stored.FailedLoginAttempts)
	}

	// E: exactly the one existing Error log line, and no rate-limit audit
	// event.
	failureLogs := logs.FilterMessage("failed to record login failure in abuse-protection layer").All()
	if len(failureLogs) != 1 {
		t.Fatalf(`"failed to record login failure..." log entries = %d, want exactly 1`, len(failureLogs))
	}
	if got := failureLogs[0].ContextMap()["error"]; got != injected.Error() {
		t.Errorf("logged error field = %v, want %q — the failure must be observed, not silently swallowed", got, injected.Error())
	}
	for _, entry := range audit.Entries {
		if entry.Action == "auth.rate_limited" {
			t.Errorf("unexpected auth.rate_limited audit event written after a RecordFailure error: %+v", entry)
		}
	}
}

// F: a RecordSuccess failure is handled the way Login already handles it
// — logged and swallowed, never changing the outcome of a login that has
// already succeeded by the time RecordSuccess runs.
func TestLogin_RecordSuccessError_LoginStillSucceeds(t *testing.T) {
	svc, users, abuseProtection, _, ctx, logs := newTestAuthServiceForFaultInjection(t, false)
	seedUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")
	injected := errors.New("redis: connection reset by peer")
	abuseProtection.FailNextRecordSuccess = injected

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Login() panicked: %v", r)
			}
		}()
		_, err = svc.Login(ctx, "org-1", "victim@example.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.1"})
	}()
	if err != nil {
		t.Fatalf("Login() with RecordSuccess failing, error = %v, want nil — a bookkeeping failure must not change an already-decided successful login", err)
	}

	resetLogs := logs.FilterMessage("failed to reset abuse-protection counters after successful login").All()
	if len(resetLogs) != 1 {
		t.Fatalf(`"failed to reset abuse-protection counters..." log entries = %d, want exactly 1`, len(resetLogs))
	}
	// The failure must be observed, not silently swallowed — the injected
	// error is expected as a structured zap.Error field on that one log
	// line, not absent from it and not folded into the response.
	if got := resetLogs[0].ContextMap()["error"]; got != injected.Error() {
		t.Errorf("logged error field = %v, want %q", got, injected.Error())
	}
}
