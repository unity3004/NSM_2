package ratelimit

import (
	"context"
	"strings"
	"testing"
	"time"
)

func testCategoryPolicy() CategoryConfig {
	return CategoryConfig{
		User:           &WindowPolicy{Window: time.Minute, Limit: 5},
		ServiceAccount: &WindowPolicy{Window: time.Minute, Limit: 50},
		IP:             &WindowPolicy{Window: time.Minute, Limit: 10},
	}
}

// --- privacy: keys never carry raw identifiers ---

func TestAPILimiter_KeysNeverContainRawIdentifiers(t *testing.T) {
	r := NewRedisAPIRateLimiter(nil, APIRateLimiterConfig{})
	const rawUserID = "user-12345-marcus"
	const rawIP = "203.0.113.42"

	keys := []string{
		r.key("secrets-read", IdentityUser, rawUserID),
		r.key("secrets-read", IdentityIP, rawIP),
	}
	for _, k := range keys {
		if strings.Contains(k, rawUserID) || strings.Contains(k, rawIP) {
			t.Errorf("Redis key %q contains a raw identifier", k)
		}
	}
}

func TestAPILimiter_KeyNamespace_IncludesCategoryAndIdentityType(t *testing.T) {
	r := NewRedisAPIRateLimiter(nil, APIRateLimiterConfig{})
	k := r.key("secrets-read", IdentityUser, "user-1")
	if !strings.HasPrefix(k, "ratelimit:api:secrets-read:user:") {
		t.Errorf("key = %q, want prefix %q", k, "ratelimit:api:secrets-read:user:")
	}
}

// --- unconfigured category / identity type: safe no-op ---

func TestAPILimiter_UnconfiguredCategory_AlwaysAllowed(t *testing.T) {
	limiter := NewRedisAPIRateLimiter(nil, APIRateLimiterConfig{Categories: map[string]CategoryConfig{}})
	decision, err := limiter.Allow(context.Background(), "some-future-category", RequestIdentity{Type: IdentityUser, ID: "user-1"})
	if err != nil {
		t.Fatalf("Allow() for an unconfigured category, error = %v, want nil", err)
	}
	if !decision.Allowed {
		t.Error("Allow() for an unconfigured category = not allowed, want allowed (no policy means no restriction)")
	}
}

func TestAPILimiter_UnconfiguredIdentityType_AlwaysAllowed(t *testing.T) {
	limiter := NewRedisAPIRateLimiter(nil, APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read": {User: &WindowPolicy{Window: time.Minute, Limit: 5}}, // no ServiceAccount policy
		},
	})
	decision, err := limiter.Allow(context.Background(), "secrets-read", RequestIdentity{Type: IdentityServiceAccount, ID: "svc-1"})
	if err != nil {
		t.Fatalf("Allow() error = %v, want nil", err)
	}
	if !decision.Allowed {
		t.Error("Allow() for an identity type this category never configured = not allowed, want allowed")
	}
}

func TestAPILimiter_EmptyIdentityID_AlwaysAllowed(t *testing.T) {
	limiter := NewRedisAPIRateLimiter(nil, APIRateLimiterConfig{Categories: map[string]CategoryConfig{"secrets-read": testCategoryPolicy()}})
	decision, err := limiter.Allow(context.Background(), "secrets-read", RequestIdentity{Type: IdentityUser, ID: ""})
	if err != nil {
		t.Fatalf("Allow() error = %v, want nil", err)
	}
	if !decision.Allowed {
		t.Error("Allow() with an empty identity ID must never itself become a shared, unbounded counter — treated as allowed/no-op")
	}
}

// --- Redis-failure posture: per-category FailOpen ---

func TestAPILimiter_UnreachableRedis_FailsClosedWhenConfigured(t *testing.T) {
	client := newUnreachableRedisClient(t)
	limiter := NewRedisAPIRateLimiter(client, APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-write": {User: &WindowPolicy{Window: time.Minute, Limit: 5}, FailOpen: false},
		},
	})
	decision, err := limiter.Allow(context.Background(), "secrets-write", RequestIdentity{Type: IdentityUser, ID: "user-1"})
	if err != nil {
		t.Fatalf("Allow() error = %v, want nil (a Redis failure must resolve to a Decision, not an error the caller must interpret)", err)
	}
	if decision.Allowed {
		t.Error("Allow() with Redis unreachable and FailOpen=false, Allowed = true, want false")
	}
}

func TestAPILimiter_UnreachableRedis_FailsOpenWhenConfigured(t *testing.T) {
	client := newUnreachableRedisClient(t)
	limiter := NewRedisAPIRateLimiter(client, APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read": {User: &WindowPolicy{Window: time.Minute, Limit: 5}, FailOpen: true},
		},
	})
	decision, err := limiter.Allow(context.Background(), "secrets-read", RequestIdentity{Type: IdentityUser, ID: "user-1"})
	if err != nil {
		t.Fatalf("Allow() error = %v, want nil", err)
	}
	if !decision.Allowed {
		t.Error("Allow() with Redis unreachable and FailOpen=true, Allowed = false, want true")
	}
}

// TestAPILimiter_FailurePostureIsPerCategory proves two categories with
// different FailOpen settings resolve a Redis outage differently in the
// same limiter instance — the objective's own "do not make a blanket
// decision for every endpoint" requirement, checked structurally rather
// than just documented.
func TestAPILimiter_FailurePostureIsPerCategory(t *testing.T) {
	client := newUnreachableRedisClient(t)
	limiter := NewRedisAPIRateLimiter(client, APIRateLimiterConfig{
		Categories: map[string]CategoryConfig{
			"secrets-read":  {User: &WindowPolicy{Window: time.Minute, Limit: 5}, FailOpen: true},
			"secrets-write": {User: &WindowPolicy{Window: time.Minute, Limit: 5}, FailOpen: false},
		},
	})
	readDecision, err := limiter.Allow(context.Background(), "secrets-read", RequestIdentity{Type: IdentityUser, ID: "user-1"})
	if err != nil || !readDecision.Allowed {
		t.Errorf("secrets-read (FailOpen=true) = %+v, %v; want Allowed=true, nil", readDecision, err)
	}
	writeDecision, err := limiter.Allow(context.Background(), "secrets-write", RequestIdentity{Type: IdentityUser, ID: "user-1"})
	if err != nil || writeDecision.Allowed {
		t.Errorf("secrets-write (FailOpen=false) = %+v, %v; want Allowed=false, nil", writeDecision, err)
	}
}
