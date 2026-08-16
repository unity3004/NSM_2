package ratelimit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// newUnreachableRedisClient points at a port nothing listens on, so every
// command fails fast with a genuine connection error — this is what lets
// the fail-open/fail-closed posture tests below exercise
// RedisAuthAbuseProtection.Check's real error-handling path without a
// live Redis server in this environment.
func newUnreachableRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // nothing listens on port 1
		DialTimeout: 200 * time.Millisecond,
		MaxRetries:  -1, // fail on the first attempt; the default retries 5 times per call, which just adds slow, noisy log output to a test that already expects failure
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// --- privacy: hashing and key construction never carry raw material ---

func TestHashIdentifier_NeverReturnsRawInput(t *testing.T) {
	for _, raw := range []string{"marcus.webb@acme.com", "203.0.113.42", "203.0.113.42|marcus.webb@acme.com"} {
		got := hashIdentifier(raw)
		if got == raw {
			t.Errorf("hashIdentifier(%q) returned the raw value unchanged", raw)
		}
		if strings.Contains(got, raw) {
			t.Errorf("hashIdentifier(%q) = %q contains the raw value", raw, got)
		}
		if len(got) != 64 { // SHA-256 hex
			t.Errorf("hashIdentifier(%q) length = %d, want 64 (SHA-256 hex)", raw, len(got))
		}
	}
}

func TestHashIdentifier_Deterministic(t *testing.T) {
	a := hashIdentifier("marcus.webb@acme.com")
	b := hashIdentifier("marcus.webb@acme.com")
	if a != b {
		t.Errorf("hashIdentifier is not deterministic: %q != %q", a, b)
	}
}

// TestRedisKeys_NeverContainRawIdentifiers proves the actual key strings
// counterKey/blockKey build never contain the raw email or IP they were
// derived from — the requirement this whole hashing scheme exists to
// satisfy, checked directly against the key text rather than assumed from
// hashIdentifier's own test above.
func TestRedisKeys_NeverContainRawIdentifiers(t *testing.T) {
	r := NewRedisAuthAbuseProtection(nil, Config{})
	const rawIP = "203.0.113.42"
	const rawAccount = "marcus.webb@acme.com"

	keys := []string{
		r.counterKey(OperationLogin, "ip", rawIP),
		r.blockKey(OperationLogin, "ip", rawIP),
		r.counterKey(OperationLogin, "account", rawAccount),
		r.blockKey(OperationLogin, "account", rawAccount),
		r.counterKey(OperationLogin, "pair", rawIP+"|"+rawAccount),
		r.blockKey(OperationLogin, "pair", rawIP+"|"+rawAccount),
	}
	for _, k := range keys {
		if strings.Contains(k, rawIP) || strings.Contains(k, rawAccount) {
			t.Errorf("Redis key %q contains a raw identifier", k)
		}
	}
}

// --- Redis-failure posture: fail-closed (the approved default) ---

func TestRedisLimiter_Check_FailsClosedOnRedisError(t *testing.T) {
	client := newUnreachableRedisClient(t)
	limiter := NewRedisAuthAbuseProtection(client, Config{
		FailClosed: true,
		Operations: map[string]OperationPolicy{
			OperationLogin: testLoginPolicy(),
		},
	})

	decision, err := limiter.Check(context.Background(), OperationLogin, Dimensions{IP: "203.0.113.1", Account: "user@example.com"})
	if err != nil {
		t.Fatalf("Check() error = %v, want nil (a Redis failure must resolve to a Decision, not an error the caller must interpret)", err)
	}
	if decision.Allowed {
		t.Error("Check() with Redis unreachable and FailClosed=true, Allowed = true, want false")
	}
}

func TestRedisLimiter_Check_FailsOpenWhenConfigured(t *testing.T) {
	client := newUnreachableRedisClient(t)
	limiter := NewRedisAuthAbuseProtection(client, Config{
		FailClosed: false,
		Operations: map[string]OperationPolicy{
			OperationLogin: testLoginPolicy(),
		},
	})

	decision, err := limiter.Check(context.Background(), OperationLogin, Dimensions{IP: "203.0.113.1", Account: "user@example.com"})
	if err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if !decision.Allowed {
		t.Error("Check() with Redis unreachable and FailClosed=false, Allowed = false, want true")
	}
}

// TestRedisLimiter_RecordFailure_ErrorNeverPanics proves the best-effort
// contract holds structurally: a Redis failure during outcome recording
// is returned as an informational error (for the caller to log), never a
// panic, and never blocks on the unreachable connection indefinitely.
func TestRedisLimiter_RecordFailure_ErrorNeverPanics(t *testing.T) {
	client := newUnreachableRedisClient(t)
	limiter := NewRedisAuthAbuseProtection(client, Config{
		Operations: map[string]OperationPolicy{
			OperationLogin: testLoginPolicy(),
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := limiter.RecordFailure(ctx, OperationLogin, Dimensions{IP: "203.0.113.1", Account: "user@example.com"})
	if err == nil {
		t.Error("RecordFailure() against an unreachable Redis = nil error, want one")
	}
}

// --- unconfigured operations are a safe no-op, never an error ---

func TestRedisLimiter_UnconfiguredOperationAlwaysAllowed(t *testing.T) {
	limiter := NewRedisAuthAbuseProtection(nil, Config{Operations: map[string]OperationPolicy{}})
	decision, err := limiter.Check(context.Background(), "some-future-endpoint", Dimensions{IP: "203.0.113.1"})
	if err != nil {
		t.Fatalf("Check() for an unconfigured operation, error = %v, want nil", err)
	}
	if !decision.Allowed {
		t.Error("Check() for an unconfigured operation = not allowed, want allowed (no policy means no restriction)")
	}
}
