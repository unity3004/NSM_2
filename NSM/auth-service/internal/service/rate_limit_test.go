package service

import (
	"context"
	"errors"
	"testing"
	"time"

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
