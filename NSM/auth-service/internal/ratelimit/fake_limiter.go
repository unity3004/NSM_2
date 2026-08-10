package ratelimit

import (
	"context"
	"sync"
	"time"
)

type fakeCounter struct {
	count     int64
	expiresAt time.Time
}

// FakeAuthAbuseProtection is an in-memory AuthAbuseProtection for tests
// that don't care about Redis itself — internal/service's own tests, for
// instance. It reuses OperationPolicy.active (the same dimension-selection
// logic RedisAuthAbuseProtection runs) and mirrors its actual policy
// semantics closely enough that a test asserting "the fifth failure
// blocks, the fourth doesn't" is testing real threshold/window/reset
// behavior, not a trivial stand-in — just backed by an in-memory map and
// wall-clock comparisons instead of Redis TTLs. It does not hash
// identifiers: a test double isn't the boundary the privacy requirement
// protects; the real Redis keys are, and internal/ratelimit's own tests
// cover those directly.
type FakeAuthAbuseProtection struct {
	mu       sync.Mutex
	cfg      Config
	counters map[string]*fakeCounter
	blocked  map[string]time.Time
}

func NewFakeAuthAbuseProtection(cfg Config) *FakeAuthAbuseProtection {
	return &FakeAuthAbuseProtection{
		cfg:      cfg,
		counters: map[string]*fakeCounter{},
		blocked:  map[string]time.Time{},
	}
}

func (f *FakeAuthAbuseProtection) active(operation string, dims Dimensions) []activeDimension {
	op, ok := f.cfg.Operations[operation]
	if !ok {
		return nil
	}
	return op.active(dims)
}

func (f *FakeAuthAbuseProtection) key(operation string, d activeDimension) string {
	return operation + "|" + d.name + "|" + d.material
}

func (f *FakeAuthAbuseProtection) Check(_ context.Context, operation string, dims Dimensions) (Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for _, d := range f.active(operation, dims) {
		k := f.key(operation, d)
		if until, ok := f.blocked[k]; ok {
			if now.Before(until) {
				return Decision{Allowed: false}, nil
			}
			delete(f.blocked, k) // block window has elapsed
		}
	}
	return Decision{Allowed: true}, nil
}

func (f *FakeAuthAbuseProtection) RecordFailure(_ context.Context, operation string, dims Dimensions) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	blockedNow := false
	for _, d := range f.active(operation, dims) {
		k := f.key(operation, d)
		c, ok := f.counters[k]
		if !ok || now.After(c.expiresAt) {
			c = &fakeCounter{expiresAt: now.Add(d.policy.Window)}
			f.counters[k] = c
		}
		c.count++
		if c.count >= d.policy.Limit {
			_, wasBlocked := f.blocked[k]
			f.blocked[k] = now.Add(d.policy.BlockDuration)
			if !wasBlocked {
				blockedNow = true
			}
		}
	}
	return blockedNow, nil
}

func (f *FakeAuthAbuseProtection) RecordSuccess(_ context.Context, operation string, dims Dimensions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.active(operation, dims) {
		if d.name == "ip" {
			continue
		}
		k := f.key(operation, d)
		delete(f.counters, k)
		delete(f.blocked, k)
	}
	return nil
}
