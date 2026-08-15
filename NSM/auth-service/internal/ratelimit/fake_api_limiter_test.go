package ratelimit

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

func newTestAPILimiter() *FakeAPIRateLimiter {
	return NewFakeAPIRateLimiter(APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read": {
				User:           &WindowPolicy{Window: time.Minute, Limit: 5},
				ServiceAccount: &WindowPolicy{Window: time.Minute, Limit: 50},
				IP:             &WindowPolicy{Window: time.Minute, Limit: 10},
			},
			"secrets-write": {
				User:     &WindowPolicy{Window: time.Minute, Limit: 3},
				FailOpen: false,
			},
		},
	})
}

// --- first request / basic allow ---

func TestFakeAPILimiter_FirstRequestAllowed(t *testing.T) {
	l := newTestAPILimiter()
	decision, err := l.Allow(context.Background(), "secrets-read", RequestIdentity{Type: IdentityUser, ID: "user-1"})
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if !decision.Allowed {
		t.Error("Allow() on a fresh identity = not allowed, want allowed")
	}
}

// --- threshold enforcement ---

func TestFakeAPILimiter_ThresholdEnforced(t *testing.T) {
	l := newTestAPILimiter()
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}

	for i := 0; i < 5; i++ {
		decision, err := l.Allow(ctx, "secrets-read", identity)
		if err != nil {
			t.Fatalf("Allow() request %d error = %v", i+1, err)
		}
		if !decision.Allowed {
			t.Fatalf("Allow() request %d = not allowed, want allowed (limit is 5)", i+1)
		}
	}

	decision, err := l.Allow(ctx, "secrets-read", identity)
	if err != nil {
		t.Fatalf("Allow() request 6 error = %v", err)
	}
	if decision.Allowed {
		t.Fatal("Allow() request 6 = allowed, want blocked (limit is 5)")
	}
	if !decision.Transitioned {
		t.Error("the 6th request (the first one over the limit) did not report a Transitioned = true")
	}
	if decision.RetryAfter <= 0 {
		t.Error("a blocked decision must report a positive RetryAfter")
	}
}

// TestFakeAPILimiter_TransitionOnlyFiresOnce proves Transitioned is only
// true on the request that crosses the limit, never on subsequent blocked
// requests in the same window — this is what keeps the middleware's audit
// event from firing once per repeated blocked request.
func TestFakeAPILimiter_TransitionOnlyFiresOnce(t *testing.T) {
	l := newTestAPILimiter()
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}

	for i := 0; i < 5; i++ {
		if _, err := l.Allow(ctx, "secrets-read", identity); err != nil {
			t.Fatalf("Allow(): %v", err)
		}
	}
	first, _ := l.Allow(ctx, "secrets-read", identity)
	if !first.Transitioned {
		t.Fatal("the first over-limit request did not transition")
	}
	for i := 0; i < 3; i++ {
		decision, err := l.Allow(ctx, "secrets-read", identity)
		if err != nil {
			t.Fatalf("Allow(): %v", err)
		}
		if decision.Allowed {
			t.Fatal("a request past the limit was unexpectedly allowed")
		}
		if decision.Transitioned {
			t.Errorf("repeated blocked request %d re-reported Transitioned = true, want false", i+1)
		}
	}
}

// --- identity/category isolation ---

func TestFakeAPILimiter_DifferentUsersDoNotShareCounters(t *testing.T) {
	l := newTestAPILimiter()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := l.Allow(ctx, "secrets-read", RequestIdentity{Type: IdentityUser, ID: "user-a"}); err != nil {
			t.Fatalf("Allow(): %v", err)
		}
	}
	if decision, _ := l.Allow(ctx, "secrets-read", RequestIdentity{Type: IdentityUser, ID: "user-a"}); decision.Allowed {
		t.Fatal("user-a should be blocked after 5 requests")
	}
	if decision, _ := l.Allow(ctx, "secrets-read", RequestIdentity{Type: IdentityUser, ID: "user-b"}); !decision.Allowed {
		t.Error("user-b's own counter was incorrectly affected by user-a's requests")
	}
}

func TestFakeAPILimiter_DifferentCategoriesDoNotShareCounters(t *testing.T) {
	l := newTestAPILimiter()
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}
	for i := 0; i < 5; i++ {
		if _, err := l.Allow(ctx, "secrets-read", identity); err != nil {
			t.Fatalf("Allow(): %v", err)
		}
	}
	if decision, _ := l.Allow(ctx, "secrets-read", identity); decision.Allowed {
		t.Fatal("secrets-read should be blocked after 5 requests")
	}
	if decision, _ := l.Allow(ctx, "secrets-write", identity); !decision.Allowed {
		t.Error("secrets-write's own counter was incorrectly affected by secrets-read's requests")
	}
}

func TestFakeAPILimiter_DifferentIdentityTypesDoNotShareCounters(t *testing.T) {
	l := newTestAPILimiter()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := l.Allow(ctx, "secrets-read", RequestIdentity{Type: IdentityUser, ID: "shared-id"}); err != nil {
			t.Fatalf("Allow(): %v", err)
		}
	}
	if decision, _ := l.Allow(ctx, "secrets-read", RequestIdentity{Type: IdentityUser, ID: "shared-id"}); decision.Allowed {
		t.Fatal("the user identity should be blocked after 5 requests")
	}
	// Same raw ID string, but a different identity Type (e.g. IP vs user) —
	// must not share the exhausted user counter.
	if decision, _ := l.Allow(ctx, "secrets-read", RequestIdentity{Type: IdentityIP, ID: "shared-id"}); !decision.Allowed {
		t.Error("an IP identity sharing the same raw ID string as an exhausted user identity was incorrectly blocked")
	}
}

// --- window expiry ---

func TestFakeAPILimiter_WindowExpiryAllowsAgain(t *testing.T) {
	l := NewFakeAPIRateLimiter(APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read": {User: &WindowPolicy{Window: 20 * time.Millisecond, Limit: 2}},
		},
	})
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}

	for i := 0; i < 2; i++ {
		if decision, err := l.Allow(ctx, "secrets-read", identity); err != nil || !decision.Allowed {
			t.Fatalf("Allow() request %d = %+v, %v; want allowed", i+1, decision, err)
		}
	}
	if decision, _ := l.Allow(ctx, "secrets-read", identity); decision.Allowed {
		t.Fatal("the 3rd request within the window should be blocked")
	}

	time.Sleep(30 * time.Millisecond)

	if decision, err := l.Allow(ctx, "secrets-read", identity); err != nil || !decision.Allowed {
		t.Errorf("Allow() after the window expired = %+v, %v; want allowed", decision, err)
	}
}

// --- unconfigured category / identity type: safe no-op, matching the real limiter ---

func TestFakeAPILimiter_UnconfiguredCategory_AlwaysAllowed(t *testing.T) {
	l := newTestAPILimiter()
	decision, err := l.Allow(context.Background(), "some-future-category", RequestIdentity{Type: IdentityUser, ID: "user-1"})
	if err != nil || !decision.Allowed {
		t.Errorf("Allow() for an unconfigured category = %+v, %v; want Allowed=true, nil", decision, err)
	}
}

func TestFakeAPILimiter_EmptyIdentityID_AlwaysAllowed(t *testing.T) {
	l := newTestAPILimiter()
	decision, err := l.Allow(context.Background(), "secrets-read", RequestIdentity{Type: IdentityUser, ID: ""})
	if err != nil || !decision.Allowed {
		t.Errorf("Allow() with an empty identity ID = %+v, %v; want Allowed=true, nil", decision, err)
	}
}

// --- fault injection ---

func TestFakeAPILimiter_FailNextAllow_ResolvesPerCategoryFailOpen(t *testing.T) {
	l := NewFakeAPIRateLimiter(APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read":  {User: &WindowPolicy{Window: time.Minute, Limit: 5}, FailOpen: true},
			"secrets-write": {User: &WindowPolicy{Window: time.Minute, Limit: 5}, FailOpen: false},
		},
	})
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}

	l.FailNextAllow = context.DeadlineExceeded
	decision, err := l.Allow(ctx, "secrets-read", identity)
	if err != nil {
		t.Fatalf("Allow() error = %v, want nil (a simulated Redis failure resolves to a Decision, not an error)", err)
	}
	if !decision.Allowed {
		t.Error("injected failure on a FailOpen=true category = not allowed, want allowed")
	}

	l.FailNextAllow = context.DeadlineExceeded
	decision, err = l.Allow(ctx, "secrets-write", identity)
	if err != nil {
		t.Fatalf("Allow() error = %v, want nil", err)
	}
	if decision.Allowed {
		t.Error("injected failure on a FailOpen=false category = allowed, want not allowed")
	}
}

func TestFakeAPILimiter_FailNextAllow_OnlyAffectsOneCall(t *testing.T) {
	l := newTestAPILimiter()
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}

	l.FailNextAllow = context.DeadlineExceeded
	if _, err := l.Allow(ctx, "secrets-read", identity); err != nil {
		t.Fatalf("Allow(): %v", err)
	}
	if l.FailNextAllow != nil {
		t.Error("FailNextAllow was not consumed by the call it was meant to affect")
	}
	// The next call should go through normal accounting, not fault injection again.
	decision, err := l.Allow(ctx, "secrets-read", identity)
	if err != nil {
		t.Fatalf("Allow(): %v", err)
	}
	if !decision.Allowed {
		t.Error("a call after the injected failure was consumed should follow normal threshold accounting")
	}
}

// --- Reset escape hatch ---

func TestFakeAPILimiter_ResetClearsCounters(t *testing.T) {
	l := newTestAPILimiter()
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}

	for i := 0; i < 6; i++ {
		if _, err := l.Allow(ctx, "secrets-read", identity); err != nil {
			t.Fatalf("Allow(): %v", err)
		}
	}
	if decision, _ := l.Allow(ctx, "secrets-read", identity); decision.Allowed {
		t.Fatal("expected the identity to be blocked before Reset")
	}

	l.Reset()

	if decision, err := l.Allow(ctx, "secrets-read", identity); err != nil || !decision.Allowed {
		t.Errorf("Allow() after Reset() = %+v, %v; want allowed", decision, err)
	}
}

// --- concurrency safety ---

// TestFakeAPILimiter_ConcurrentRequestsRespectTheLimit drives many
// goroutines at the same identity simultaneously and asserts that exactly
// Limit of them are allowed — proving the fake's internal locking
// (mirroring the real limiter's atomic Lua script) prevents a race from
// letting more requests through than the configured limit.
func TestFakeAPILimiter_ConcurrentRequestsRespectTheLimit(t *testing.T) {
	l := NewFakeAPIRateLimiter(APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read": {User: &WindowPolicy{Window: time.Minute, Limit: 20}},
		},
	})
	ctx := context.Background()
	identity := RequestIdentity{Type: IdentityUser, ID: "user-1"}

	const attempts = 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			decision, err := l.Allow(ctx, "secrets-read", identity)
			if err != nil {
				t.Errorf("Allow() goroutine %d error = %v", n, err)
				return
			}
			if decision.Allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if allowedCount != 20 {
		t.Errorf("allowedCount = %d, want exactly 20 (the configured limit) out of %d concurrent attempts", allowedCount, attempts)
	}
}

func TestFakeAPILimiter_ConcurrentDifferentIdentitiesEachGetFullLimit(t *testing.T) {
	l := NewFakeAPIRateLimiter(APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read": {User: &WindowPolicy{Window: time.Minute, Limit: 5}},
		},
	})
	ctx := context.Background()

	const identities = 10
	const attemptsPerIdentity = 5
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0

	for u := 0; u < identities; u++ {
		id := "user-" + strconv.Itoa(u)
		for i := 0; i < attemptsPerIdentity; i++ {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				decision, err := l.Allow(ctx, "secrets-read", RequestIdentity{Type: IdentityUser, ID: id})
				if err != nil {
					t.Errorf("Allow() error = %v", err)
					return
				}
				if decision.Allowed {
					mu.Lock()
					allowedCount++
					mu.Unlock()
				}
			}(id)
		}
	}
	wg.Wait()

	if allowedCount != identities*attemptsPerIdentity {
		t.Errorf("allowedCount = %d, want %d (every identity has its own independent limit)", allowedCount, identities*attemptsPerIdentity)
	}
}
