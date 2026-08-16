package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// --- login: 429 + Retry-After ---

func TestLoginHandler_RateLimited(t *testing.T) {
	users := mocks.NewFakeUserRepository()
	sessions := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	loginHistory := mocks.NewFakeLoginHistoryRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error { return fn(audit) }
	abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationLogin: {
				Account: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 5, BlockDuration: 15 * time.Minute},
			},
		},
	})
	passwords := security.NewPasswordService(security.Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32})
	svc := service.NewAuthService(service.AuthServiceDeps{
		Users:               users,
		Sessions:            sessions,
		RefreshTokens:       refreshTokens,
		LoginHistory:        loginHistory,
		Tokens:              util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		Passwords:           passwords,
		RefreshTTL:          30 * 24 * time.Hour,
		AuditTx:             auditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: 60 * time.Second,
	})
	h := &authHandler{svc: svc}

	seedLoginUser(t, users, "victim@example.com", "Tr0ub4dor&3xample!")
	for i := 0; i < 5; i++ {
		_, _ = abuseProtection.RecordFailure(t.Context(), ratelimit.OperationLogin, ratelimit.Dimensions{Account: "victim@example.com"})
	}

	rec := httptest.NewRecorder()
	h.login(rec, loginRequest(t, `{"email":"victim@example.com","password":"Tr0ub4dor&3xample!"}`))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want %q", got, "60")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	errObj, _ := body["error"].(map[string]any)
	if errObj["code"] != "RATE_LIMITED" {
		t.Errorf("error code = %v, want RATE_LIMITED", errObj["code"])
	}
	// The response must never name which dimension (ip/account/pair)
	// triggered the block, nor any internal counter/threshold value.
	lower := strings.ToLower(rec.Body.String())
	for _, leak := range []string{"ip", "account", "pair", "dimension", "counter", "threshold", "redis"} {
		if strings.Contains(lower, leak) {
			t.Errorf("response body leaks internal rate-limit detail (%q): %s", leak, rec.Body.String())
		}
	}
}

// TestLoginHandler_RateLimited_UnknownAndKnownAccountLookIdentical proves
// the 429 response is byte-identical regardless of whether the blocked
// account actually exists — the same anti-enumeration guarantee the 401
// path already has, extended to the rate-limit path.
func TestLoginHandler_RateLimited_UnknownAndKnownAccountLookIdentical(t *testing.T) {
	newHandler := func(t *testing.T) (*authHandler, *ratelimit.FakeAuthAbuseProtection, *mocks.FakeUserRepository) {
		users := mocks.NewFakeUserRepository()
		sessions := mocks.NewFakeSessionRepository()
		refreshTokens := mocks.NewFakeRefreshTokenRepository()
		loginHistory := mocks.NewFakeLoginHistoryRepository()
		abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
			Operations: map[string]ratelimit.OperationPolicy{
				ratelimit.OperationLogin: {
					Account: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 5, BlockDuration: 15 * time.Minute},
				},
			},
		})
		passwords := security.NewPasswordService(security.Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32})
		svc := service.NewAuthService(service.AuthServiceDeps{
			Users: users, Sessions: sessions, RefreshTokens: refreshTokens, LoginHistory: loginHistory,
			Tokens: util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute), Passwords: passwords,
			RefreshTTL: 30 * 24 * time.Hour, AbuseProtection: abuseProtection, RateLimitRetryAfter: 60 * time.Second,
		})
		return &authHandler{svc: svc}, abuseProtection, users
	}

	hKnown, abuseKnown, usersKnown := newHandler(t)
	seedLoginUser(t, usersKnown, "victim@example.com", "Tr0ub4dor&3xample!")
	for i := 0; i < 5; i++ {
		_, _ = abuseKnown.RecordFailure(t.Context(), ratelimit.OperationLogin, ratelimit.Dimensions{Account: "victim@example.com"})
	}
	known := httptest.NewRecorder()
	hKnown.login(known, loginRequest(t, `{"email":"victim@example.com","password":"whatever-password"}`))

	hUnknown, abuseUnknown, _ := newHandler(t)
	for i := 0; i < 5; i++ {
		_, _ = abuseUnknown.RecordFailure(t.Context(), ratelimit.OperationLogin, ratelimit.Dimensions{Account: "nobody@example.com"})
	}
	unknown := httptest.NewRecorder()
	hUnknown.login(unknown, loginRequest(t, `{"email":"nobody@example.com","password":"whatever-password"}`))

	if known.Code != http.StatusTooManyRequests || unknown.Code != http.StatusTooManyRequests {
		t.Fatalf("status codes = %d / %d, want both %d", known.Code, unknown.Code, http.StatusTooManyRequests)
	}
	if known.Body.String() != unknown.Body.String() {
		t.Errorf("responses differ:\nknown account:   %s\nunknown account: %s", known.Body.String(), unknown.Body.String())
	}
}

// --- refresh: 429 + Retry-After ---

func TestRefreshHandler_RateLimited(t *testing.T) {
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	sessionRepo := mocks.NewFakeSessionRepository()
	sessions := service.NewSessionService(sessionRepo)
	abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationRefresh: {
				IP: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 30, BlockDuration: 15 * time.Minute},
			},
		},
	})
	keys, err := security.LoadSigningKeySet("key-1", generateTestEd25519PrivateKeyPEMForHandler(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	tokens := security.NewTokenService(keys, "auth-service", 10*time.Minute)
	svc := service.NewRefreshTokenService(service.RefreshTokenServiceDeps{
		RefreshTokens: refreshTokens, Sessions: sessions, Tokens: tokens,
		AccessTokenAudience: "auth-service", AccessTokenTTL: 10 * time.Minute, RefreshTTL: 7 * 24 * time.Hour,
		AbuseProtection: abuseProtection, RateLimitRetryAfter: 60 * time.Second,
	})
	h := &refreshHandler{svc: svc}

	for i := 0; i < 30; i++ {
		_, _ = abuseProtection.RecordFailure(t.Context(), ratelimit.OperationRefresh, ratelimit.Dimensions{IP: "203.0.113.1"})
	}

	req := refreshHTTPRequest(t, `{"refresh_token":"anything"}`)
	// A direct client at this address, not a header — with no trusted
	// proxy configured (SetTrustedProxies defaults to empty), clientIP
	// now correctly ignores X-Forwarded-For entirely (see
	// util.ResolveClientIP's own doc comment on why trusting it
	// unconditionally was a spoofable rate-limit bypass), so the request
	// must arrive from this IP directly for the pre-loaded block above to
	// apply to it.
	req.RemoteAddr = "203.0.113.1:54321"
	rec := httptest.NewRecorder()
	h.refresh(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want %q", got, "60")
	}
}
