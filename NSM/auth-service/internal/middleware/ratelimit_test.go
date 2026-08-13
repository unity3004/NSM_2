package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/util"
)

// stubAPILimiter gives each test full, direct control over the decision
// RateLimit sees — including an injected Go error, which
// ratelimit.RedisAPIRateLimiter's own contract says should never happen
// in practice (see that type's Allow doc comment), but which
// RateLimit must still handle safely since it is a real branch in the
// code.
type stubAPILimiter struct {
	decision  ratelimit.APIDecision
	err       error
	lastCat   string
	lastIdent ratelimit.RequestIdentity
	calls     int
}

func (s *stubAPILimiter) Allow(_ context.Context, category string, identity ratelimit.RequestIdentity) (ratelimit.APIDecision, error) {
	s.calls++
	s.lastCat = category
	s.lastIdent = identity
	return s.decision, s.err
}

func allowHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func rateLimitRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	ctx := util.WithRequestID(req.Context(), "req-test-ratelimit")
	return req.WithContext(ctx)
}

func rateLimitRequestWithClaims(subject, sessionID string) *http.Request {
	req := rateLimitRequest()
	ctx := withClaims(req.Context(), &util.Claims{Subject: subject, SessionID: sessionID})
	return req.WithContext(ctx)
}

// --- allow / deny basics ---

func TestRateLimit_Allowed_PassesThrough(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: true}}
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequest())

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if limiter.calls != 1 {
		t.Errorf("limiter.Allow was called %d times, want 1", limiter.calls)
	}
}

func TestRateLimit_Denied_Returns429WithRetryAfter(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: false, RetryAfter: 42 * time.Second}}
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequest())

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q, want %q", got, "42")
	}
}

func TestRateLimit_Denied_RetryAfterNeverLessThanOne(t *testing.T) {
	// A sub-second RetryAfter (e.g. a window about to roll over) must not
	// round down to "0" — Retry-After: 0 tells a client to retry
	// immediately, defeating the throttle.
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: false, RetryAfter: 100 * time.Millisecond}}
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequest())

	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want %q (rounded up, never 0)", got, "1")
	}
}

func TestRateLimit_Denied_ResponseShapeMatchesErrorEnvelope(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: false, RetryAfter: time.Second}}
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequest())

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body=%s)", err, rec.Body.String())
	}
	if body.Error.Code != "RATE_LIMITED" {
		t.Errorf("error.code = %q, want %q", body.Error.Code, "RATE_LIMITED")
	}
	if body.Error.Message == "" {
		t.Error("error.message must not be empty")
	}
	// The 429 body must never leak anything about Redis, keys, or counters.
	for _, leak := range []string{"redis", "Redis", "ratelimit:", "TTL", "INCR"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("response body leaks internal detail %q: %s", leak, rec.Body.String())
		}
	}
}

// --- identity resolution ---

func TestRateLimit_UnauthenticatedRequest_UsesIPIdentity(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: true}}
	handler := RateLimit(limiter, nil, "auth-register")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequest())

	if limiter.lastIdent.Type != ratelimit.IdentityIP {
		t.Errorf("identity.Type = %v, want %v", limiter.lastIdent.Type, ratelimit.IdentityIP)
	}
	if limiter.lastIdent.ID != "203.0.113.7" {
		t.Errorf("identity.ID = %q, want %q", limiter.lastIdent.ID, "203.0.113.7")
	}
}

func TestRateLimit_AuthenticatedHumanUser_UsesUserIdentity(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: true}}
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-1", "session-abc"))

	if limiter.lastIdent.Type != ratelimit.IdentityUser {
		t.Errorf("identity.Type = %v, want %v", limiter.lastIdent.Type, ratelimit.IdentityUser)
	}
	if limiter.lastIdent.ID != "user-1" {
		t.Errorf("identity.ID = %q, want %q (claims.Subject, not email)", limiter.lastIdent.ID, "user-1")
	}
}

func TestRateLimit_ServiceAccount_UsesServiceAccountIdentity(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: true}}
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	rec := httptest.NewRecorder()
	// Empty SessionID is the existing codebase signal for "this token has
	// no session" — i.e. a service account, not a human login.
	handler.ServeHTTP(rec, rateLimitRequestWithClaims("svc-1", ""))

	if limiter.lastIdent.Type != ratelimit.IdentityServiceAccount {
		t.Errorf("identity.Type = %v, want %v", limiter.lastIdent.Type, ratelimit.IdentityServiceAccount)
	}
	if limiter.lastIdent.ID != "svc-1" {
		t.Errorf("identity.ID = %q, want %q", limiter.lastIdent.ID, "svc-1")
	}
}

// --- category dispatch ---

func TestRateLimit_PassesConfiguredCategoryToLimiter(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: true}}
	handler := RateLimit(limiter, nil, "policy-admin")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequest())

	if limiter.lastCat != "policy-admin" {
		t.Errorf("category passed to Allow = %q, want %q", limiter.lastCat, "policy-admin")
	}
}

// --- limiter error handling: fail open at the middleware boundary ---

func TestRateLimit_LimiterReturnsError_FailsOpen(t *testing.T) {
	limiter := &stubAPILimiter{err: errors.New("unexpected failure")}
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequest())

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (an Allow() error must fail open, not block a legitimate request on a programming error)", rec.Code, http.StatusOK)
	}
}

// --- audit: only on transition, never a flood ---

func TestRateLimit_Denied_Transitioned_RecordsRateLimitExceededEvent(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: false, RetryAfter: time.Second, Transitioned: true}}
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	handler := RateLimit(limiter, auditTx, "secrets-write")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-1", "session-abc"))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	found := false
	for _, e := range audit.Entries {
		if e.Action != "rate_limit.exceeded" {
			continue
		}
		found = true
		if e.ActorID == nil || *e.ActorID != "user-1" {
			t.Errorf("ActorID = %v, want %q", e.ActorID, "user-1")
		}
		if e.ResourceType == nil || *e.ResourceType != "secrets-write" {
			t.Errorf("ResourceType = %v, want %q", e.ResourceType, "secrets-write")
		}
		if cat, _ := e.Metadata["category"].(string); cat != "secrets-write" {
			t.Errorf("Metadata[category] = %v, want %q", e.Metadata["category"], "secrets-write")
		}
	}
	if !found {
		t.Error("no rate_limit.exceeded audit entry was recorded on a transitioned denial")
	}
}

func TestRateLimit_Denied_NotTransitioned_DoesNotRecordAgain(t *testing.T) {
	// A repeated blocked request within the same throttled window must not
	// re-fire the audit event — this is the objective's own "do not create
	// an audit event for every harmless request; avoid audit-log flooding"
	// requirement, checked directly against the middleware rather than
	// just the limiter's own Transitioned semantics.
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: false, RetryAfter: time.Second, Transitioned: false}}
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	handler := RateLimit(limiter, auditTx, "secrets-write")(allowHandler())
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-1", "session-abc"))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d: status = %d, want %d", i+1, rec.Code, http.StatusTooManyRequests)
		}
	}

	for _, e := range audit.Entries {
		if e.Action == "rate_limit.exceeded" {
			t.Fatalf("a non-transitioned denial recorded a rate_limit.exceeded audit entry: %+v", e)
		}
	}
}

func TestRateLimit_Allowed_DoesNotRecordAnything(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: true}}
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	handler := RateLimit(limiter, auditTx, "secrets-read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-1", "session-abc"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if len(audit.Entries) != 0 {
		t.Errorf("Entries = %v, want none", audit.Entries)
	}
}

func TestRateLimit_NilAuditTx_StillDeniesCorrectly(t *testing.T) {
	limiter := &stubAPILimiter{decision: ratelimit.APIDecision{Allowed: false, RetryAfter: time.Second, Transitioned: true}}
	handler := RateLimit(limiter, nil, "secrets-write")(allowHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-1", "session-abc"))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d — a nil auditTx must not affect the throttle decision itself", rec.Code, http.StatusTooManyRequests)
	}
}

// --- integration with the real fake limiter: end-to-end threshold behavior ---

func TestRateLimit_WithFakeAPIRateLimiter_EnforcesRealThreshold(t *testing.T) {
	limiter := ratelimit.NewFakeAPIRateLimiter(ratelimit.APIRateLimiterConfig{
		Categories: map[string]ratelimit.CategoryConfig{
			"secrets-read": {User: &ratelimit.WindowPolicy{Window: time.Minute, Limit: 3}},
		},
	})
	handler := RateLimit(limiter, nil, "secrets-read")(allowHandler())

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-1", "session-abc"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-1", "session-abc"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request 4: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	// A different user must have their own, unaffected limit.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, rateLimitRequestWithClaims("user-2", "session-def"))
	if rec.Code != http.StatusOK {
		t.Errorf("a different user's request: status = %d, want %d (independent counter)", rec.Code, http.StatusOK)
	}
}
