package ratelimit

import (
	"context"
	"sync"
	"time"
)

type apiFakeCounter struct {
	count     int64
	expiresAt time.Time
}

// FakeAPIRateLimiter is an in-memory APIRateLimiter for tests that don't
// care about Redis itself — internal/middleware's own rate-limit
// middleware tests, in particular. It mirrors RedisAPIRateLimiter's real
// fixed-window/TTL/transition semantics closely enough that a test
// asserting "the Nth request is throttled, the (N-1)th isn't" is testing
// real threshold/window behavior, not a trivial stand-in — just backed by
// an in-memory map and wall-clock comparisons instead of Redis TTLs. It
// does not hash identifiers, the same "a test double isn't the boundary
// the privacy requirement protects" reasoning FakeAuthAbuseProtection's
// own doc comment already gives.
type FakeAPIRateLimiter struct {
	mu       sync.Mutex
	cfg      APIRateLimiterConfig
	counters map[string]*apiFakeCounter
	// FailNextAllow, if non-nil, is consumed by the next Allow call and
	// resolved to APIDecision{Allowed: cat.FailOpen} — the same
	// fault-injection convention as FakeAuthAbuseProtection.FailNextCheck,
	// for the identical reason: RedisAPIRateLimiter.Allow never returns a
	// Redis connectivity problem as a Go error either (see that method's
	// own doc comment), so a fake that just returned the raw injected
	// error would test a code path no real caller can actually reach.
	FailNextAllow error
}

func NewFakeAPIRateLimiter(cfg APIRateLimiterConfig) *FakeAPIRateLimiter {
	return &FakeAPIRateLimiter{cfg: cfg, counters: map[string]*apiFakeCounter{}}
}

func (f *FakeAPIRateLimiter) key(category string, identity RequestIdentity) string {
	return category + "|" + string(identity.Type) + "|" + identity.ID
}

func (f *FakeAPIRateLimiter) Allow(_ context.Context, category string, identity RequestIdentity) (APIDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cat, ok := f.cfg.Categories[category]
	if !ok {
		return APIDecision{Allowed: true}, nil
	}
	policy := cat.policyFor(identity.Type)
	if policy == nil || identity.ID == "" {
		return APIDecision{Allowed: true}, nil
	}

	if f.FailNextAllow != nil {
		f.FailNextAllow = nil
		return APIDecision{Allowed: cat.FailOpen}, nil
	}

	now := time.Now()
	k := f.key(category, identity)
	c, ok := f.counters[k]
	if !ok || now.After(c.expiresAt) {
		c = &apiFakeCounter{expiresAt: now.Add(policy.Window)}
		f.counters[k] = c
	}
	c.count++

	if c.count > policy.Limit {
		return APIDecision{
			Allowed:      false,
			RetryAfter:   c.expiresAt.Sub(now),
			Transitioned: c.count == policy.Limit+1,
		}, nil
	}
	return APIDecision{Allowed: true}, nil
}

// Reset clears every counter — a test-only escape hatch for a test that
// wants to prove an identity is allowed again in a later, independent
// phase without waiting out a real Window.
func (f *FakeAPIRateLimiter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counters = map[string]*apiFakeCounter{}
}
