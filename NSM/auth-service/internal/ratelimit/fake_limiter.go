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
	// FailNextCheck/FailNextRecordFailure/FailNextRecordSuccess, if
	// non-nil, are consumed by the next matching call and reset to nil —
	// the same fault-injection convention used throughout this codebase
	// (FakeSessionRepository.FailNextRevoke, FakeUserRepository.FailNextGetByEmail,
	// etc.), added for Milestone 6C's gap-analysis follow-up: proving
	// AuthService/RefreshTokenService behave correctly when the
	// abuse-protection layer itself fails.
	//
	// FailNextRecordFailure/FailNextRecordSuccess are returned verbatim —
	// RecordFailure/RecordSuccess are always best-effort, so a caller
	// seeing this exact error and logging-then-swallowing it is the
	// correct, already-implemented behavior being tested, not a new one.
	//
	// FailNextCheck is different, deliberately: RedisAuthAbuseProtection.Check
	// never returns a Redis connectivity problem as a Go error — it
	// resolves the configured FailClosed posture internally and returns a
	// plain Decision (see that method's own doc comment). Consuming
	// FailNextCheck here does the same, resolving to
	// Decision{Allowed: !cfg.FailClosed} rather than returning the
	// injected error — matching the real implementation's contract
	// exactly, since a version that just returned the raw error would
	// test a code path AuthService.Login doesn't actually have (Login
	// discards Check's error return and only reads Decision.Allowed).
	FailNextCheck         error
	FailNextRecordFailure error
	FailNextRecordSuccess error
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
	if f.FailNextCheck != nil {
		f.FailNextCheck = nil
		return Decision{Allowed: !f.cfg.FailClosed}, nil
	}
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
	if f.FailNextRecordFailure != nil {
		err := f.FailNextRecordFailure
		f.FailNextRecordFailure = nil
		return false, err
	}
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
	if f.FailNextRecordSuccess != nil {
		err := f.FailNextRecordSuccess
		f.FailNextRecordSuccess = nil
		return err
	}
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
