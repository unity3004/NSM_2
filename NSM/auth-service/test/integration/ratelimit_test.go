//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/acme/auth-service/internal/ratelimit"
)

func connectForRateLimitTest(t *testing.T) *goredis.Client {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR not set; see docker/docker-compose.yml for a local Redis")
	}
	client := goredis.NewClient(&goredis.Options{Addr: addr, DialTimeout: 5 * time.Second})
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestRedisAuthAbuseProtection_TTLIsApplied is the real-Redis half of
// requirement #7/#8 (TTL): proves the counter key Redis actually creates
// carries a real, positive TTL — internal/ratelimit's fake-backed tests
// can only assert the fake's own simulated expiry logic, not that the
// real Lua script's EXPIRE call actually reached Redis with the right
// value.
func TestRedisAuthAbuseProtection_TTLIsApplied(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	limiter := ratelimit.NewRedisAuthAbuseProtection(client, ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationLogin: {
				Account: &ratelimit.DimensionPolicy{Window: 5 * time.Minute, Limit: 100, BlockDuration: 5 * time.Minute},
			},
		},
	})

	if _, err := limiter.RecordFailure(ctx, ratelimit.OperationLogin, ratelimit.Dimensions{Account: "victim@example.com"}); err != nil {
		t.Fatalf("RecordFailure(): %v", err)
	}

	keys, err := client.Keys(ctx, "ratelimit:login:account:counter:*").Result()
	if err != nil {
		t.Fatalf("KEYS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("counter keys = %d, want exactly 1", len(keys))
	}
	ttl, err := client.TTL(ctx, keys[0]).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		t.Errorf("TTL = %v, want a positive value at most 5m (the configured window)", ttl)
	}
}

// TestRedisAuthAbuseProtection_BlockKeyExpires proves a real block key
// actually stops blocking once Redis expires it — not just that the fake's
// simulated wall-clock comparison does.
func TestRedisAuthAbuseProtection_BlockKeyExpires(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	limiter := ratelimit.NewRedisAuthAbuseProtection(client, ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationLogin: {
				Account: &ratelimit.DimensionPolicy{Window: time.Minute, Limit: 1, BlockDuration: 2 * time.Second},
			},
		},
	})
	dims := ratelimit.Dimensions{Account: "victim@example.com"}

	if _, err := limiter.RecordFailure(ctx, ratelimit.OperationLogin, dims); err != nil {
		t.Fatalf("RecordFailure(): %v", err)
	}
	decision, err := limiter.Check(ctx, ratelimit.OperationLogin, dims)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected blocked immediately after crossing the threshold")
	}

	time.Sleep(3 * time.Second)
	decision, err = limiter.Check(ctx, ratelimit.OperationLogin, dims)
	if err != nil {
		t.Fatalf("Check(): %v", err)
	}
	if !decision.Allowed {
		t.Error("block did not expire after its configured duration")
	}
}

// TestRedisAuthAbuseProtection_ConcurrentFailuresCannotBypassThreshold is
// the real-Redis half of requirements #8/#9/#15: proves the Lua script's
// atomicity — not a Go-level mutex like the fake's — is what prevents two
// concurrent RecordFailure calls for the same identifier from both
// slipping past the threshold. internal/ratelimit's own
// TestFakeLimiter_ConcurrentFailuresCannotBypassThreshold proves the same
// property against the fake; this is the proof a fake cannot give no
// matter how it's written, since its "atomicity" is a Go mutex, not
// evidence about Redis's own EVAL semantics.
func TestRedisAuthAbuseProtection_ConcurrentFailuresCannotBypassThreshold(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	const limit = 50
	limiter := ratelimit.NewRedisAuthAbuseProtection(client, ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationLogin: {
				Account: &ratelimit.DimensionPolicy{Window: time.Minute, Limit: limit, BlockDuration: time.Minute},
			},
		},
	})
	dims := ratelimit.Dimensions{Account: "victim@example.com"}

	const concurrency = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	blockTransitions := 0
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blocked, err := limiter.RecordFailure(ctx, ratelimit.OperationLogin, dims)
			if err != nil {
				t.Errorf("RecordFailure(): %v", err)
				return
			}
			if blocked {
				mu.Lock()
				blockTransitions++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if blockTransitions != 1 {
		t.Errorf("block transitions = %d, want exactly 1 — two concurrent calls both reporting a transition means the threshold check raced", blockTransitions)
	}

	counterKeys, err := client.Keys(ctx, "ratelimit:login:account:counter:*").Result()
	if err != nil {
		t.Fatalf("KEYS: %v", err)
	}
	if len(counterKeys) != 1 {
		t.Fatalf("counter keys = %d, want exactly 1", len(counterKeys))
	}
	count, err := client.Get(ctx, counterKeys[0]).Int()
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if count != concurrency {
		t.Errorf("counter = %d, want exactly %d (no lost updates from concurrent INCRs)", count, concurrency)
	}
}

// --- Sprint 4 Task 4: general-purpose APIRateLimiter, real-Redis half ---
//
// internal/ratelimit's own api_limiter_test.go and fake_api_limiter_test.go
// prove the algorithm and the fake double; these tests prove the same
// properties against real Redis specifically where a fake cannot: TTL
// actually reaching Redis, atomicity coming from the Lua script's EVAL
// semantics rather than a Go mutex, and — the one property no single
// in-process client can demonstrate at all — that the limit is shared
// correctly across multiple independent client connections, standing in
// for multiple application instances behind a load balancer (the
// objective's own "the limit must not reset merely because traffic
// reaches a different application instance" requirement).

func testAPICategoryConfig(limit int64, window time.Duration, failOpen bool) map[string]ratelimit.CategoryConfig {
	return map[string]ratelimit.CategoryConfig{
		"secrets-read": {
			User:     &ratelimit.WindowPolicy{Window: window, Limit: limit},
			FailOpen: failOpen,
		},
	}
}

func TestRedisAPILimiter_TTLIsApplied(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	limiter := ratelimit.NewRedisAPIRateLimiter(client, ratelimit.APIRateLimiterConfig{
		Categories: testAPICategoryConfig(100, 5*time.Minute, false),
	})

	if _, err := limiter.Allow(ctx, "secrets-read", ratelimit.RequestIdentity{Type: ratelimit.IdentityUser, ID: "user-1"}); err != nil {
		t.Fatalf("Allow(): %v", err)
	}

	keys, err := client.Keys(ctx, "ratelimit:api:secrets-read:user:*").Result()
	if err != nil {
		t.Fatalf("KEYS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("counter keys = %d, want exactly 1", len(keys))
	}
	ttl, err := client.TTL(ctx, keys[0]).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		t.Errorf("TTL = %v, want a positive value at most 5m (the configured window) — every rate-limit key must expire on its own", ttl)
	}
}

// TestRedisAPILimiter_KeyDoesNotContainRawIdentifier is the real-Redis half
// of the "never place sensitive plaintext identifiers in keys" requirement
// — internal/ratelimit's own unit test proves the key() function's output
// never contains the raw ID, this proves the exact key Redis actually
// stores under carries the same property.
func TestRedisAPILimiter_KeyDoesNotContainRawIdentifier(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	limiter := ratelimit.NewRedisAPIRateLimiter(client, ratelimit.APIRateLimiterConfig{
		Categories: testAPICategoryConfig(100, time.Minute, false),
	})
	const rawUserID = "user-victim-98765"

	if _, err := limiter.Allow(ctx, "secrets-read", ratelimit.RequestIdentity{Type: ratelimit.IdentityUser, ID: rawUserID}); err != nil {
		t.Fatalf("Allow(): %v", err)
	}

	keys, err := client.Keys(ctx, "ratelimit:api:*").Result()
	if err != nil {
		t.Fatalf("KEYS: %v", err)
	}
	for _, k := range keys {
		if strings.Contains(k, rawUserID) {
			t.Errorf("Redis key %q contains the raw identifier", k)
		}
	}
}

// TestRedisAPILimiter_WindowExpiryResetsTheCounter proves a real Redis TTL
// expiry — not the fake's simulated wall-clock comparison — actually lets
// a throttled identity through again once its window rolls over.
func TestRedisAPILimiter_WindowExpiryResetsTheCounter(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	limiter := ratelimit.NewRedisAPIRateLimiter(client, ratelimit.APIRateLimiterConfig{
		Categories: testAPICategoryConfig(1, 2*time.Second, false),
	})
	identity := ratelimit.RequestIdentity{Type: ratelimit.IdentityUser, ID: "user-1"}

	decision, err := limiter.Allow(ctx, "secrets-read", identity)
	if err != nil || !decision.Allowed {
		t.Fatalf("Allow() request 1 = %+v, %v; want allowed", decision, err)
	}
	decision, err = limiter.Allow(ctx, "secrets-read", identity)
	if err != nil {
		t.Fatalf("Allow(): %v", err)
	}
	if decision.Allowed {
		t.Fatal("Allow() request 2 within the window = allowed, want blocked (limit is 1)")
	}

	time.Sleep(3 * time.Second)

	decision, err = limiter.Allow(ctx, "secrets-read", identity)
	if err != nil {
		t.Fatalf("Allow(): %v", err)
	}
	if !decision.Allowed {
		t.Error("Allow() after the window expired = blocked, want allowed")
	}
}

// TestRedisAPILimiter_ConcurrentRequestsCannotBypassThreshold is the
// real-Redis half of "avoid race conditions in distributed counting" —
// proves the Lua script's atomicity, not a Go mutex, is what keeps
// concurrent Allow calls for the same identity from letting more than
// Limit requests through.
func TestRedisAPILimiter_ConcurrentRequestsCannotBypassThreshold(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	const limit = 50
	limiter := ratelimit.NewRedisAPIRateLimiter(client, ratelimit.APIRateLimiterConfig{
		Categories: testAPICategoryConfig(limit, time.Minute, false),
	})
	identity := ratelimit.RequestIdentity{Type: ratelimit.IdentityUser, ID: "user-1"}

	const concurrency = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, err := limiter.Allow(ctx, "secrets-read", identity)
			if err != nil {
				t.Errorf("Allow(): %v", err)
				return
			}
			if decision.Allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowedCount != limit {
		t.Errorf("allowedCount = %d, want exactly %d — a race would let more than the configured limit through", allowedCount, limit)
	}

	counterKeys, err := client.Keys(ctx, "ratelimit:api:secrets-read:user:*").Result()
	if err != nil {
		t.Fatalf("KEYS: %v", err)
	}
	if len(counterKeys) != 1 {
		t.Fatalf("counter keys = %d, want exactly 1", len(counterKeys))
	}
	count, err := client.Get(ctx, counterKeys[0]).Int()
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if count != concurrency {
		t.Errorf("counter = %d, want exactly %d (no lost updates from concurrent INCRs)", count, concurrency)
	}
}

// TestRedisAPILimiter_SharedAcrossMultipleClientInstances is the one
// property no single-process, single-client test — fake or real — can
// demonstrate: two entirely independent RedisAPIRateLimiter instances,
// each with its own *redis.Client connection (standing in for two
// separate application server instances behind a load balancer), enforce
// exactly one shared limit because the counter lives in Redis, not in
// either process's memory. This is the objective's own "the limit must
// not reset merely because traffic reaches a different application
// instance" requirement, proven directly rather than inferred from the
// key format alone.
func TestRedisAPILimiter_SharedAcrossMultipleClientInstances(t *testing.T) {
	client := connectForRateLimitTest(t)
	ctx := context.Background()
	client.FlushDB(ctx)

	addr := os.Getenv("REDIS_ADDR")
	cfg := ratelimit.APIRateLimiterConfig{Categories: testAPICategoryConfig(10, time.Minute, false)}

	instanceA := ratelimit.NewRedisAPIRateLimiter(client, cfg)
	clientB := goredis.NewClient(&goredis.Options{Addr: addr, DialTimeout: 5 * time.Second})
	t.Cleanup(func() { _ = clientB.Close() })
	instanceB := ratelimit.NewRedisAPIRateLimiter(clientB, cfg)

	identity := ratelimit.RequestIdentity{Type: ratelimit.IdentityUser, ID: "user-1"}

	allowed := 0
	for i := 0; i < 10; i++ {
		limiter := instanceA
		if i%2 == 1 {
			limiter = instanceB
		}
		decision, err := limiter.Allow(ctx, "secrets-read", identity)
		if err != nil {
			t.Fatalf("Allow() (alternating instance %d): %v", i, err)
		}
		if decision.Allowed {
			allowed++
		} else {
			t.Fatalf("request %d (instance %s) was blocked before the shared limit of 10 was reached", i+1, map[bool]string{true: "B", false: "A"}[i%2 == 1])
		}
	}

	// The 11th request, alternating instance once more, must be blocked —
	// proving the two "application instances" share one counter, not one
	// each.
	decision, err := instanceA.Allow(ctx, "secrets-read", identity)
	if err != nil {
		t.Fatalf("Allow(): %v", err)
	}
	if decision.Allowed {
		t.Error("the 11th request across two independent client instances = allowed, want blocked (they must share one Redis-backed counter)")
	}
}

// TestRedisAPILimiter_FailOpenWhenRedisUnreachable proves the real
// implementation's Redis-outage posture matches the documented per-category
// FailOpen contract against an actual (albeit refused) connection, not
// just the unit tests' shared unreachable-client helper's assumptions.
func TestRedisAPILimiter_FailOpenWhenRedisUnreachable(t *testing.T) {
	// Reuses the same "unreachable Redis" shape as
	// TestRedisAuthAbuseProtection's own unit tests: a real client pointed
	// at a port nothing listens on, so calls fail at the network layer.
	client := goredis.NewClient(&goredis.Options{
		Addr:            "127.0.0.1:1",
		DialTimeout:     200 * time.Millisecond,
		ReadTimeout:     200 * time.Millisecond,
		MaxRetries:      1,
		MinRetryBackoff: 10 * time.Millisecond,
		MaxRetryBackoff: 20 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	limiter := ratelimit.NewRedisAPIRateLimiter(client, ratelimit.APIRateLimiterConfig{
		Categories: testAPICategoryConfig(5, time.Minute, true),
	})
	decision, err := limiter.Allow(context.Background(), "secrets-read", ratelimit.RequestIdentity{Type: ratelimit.IdentityUser, ID: "user-1"})
	if err != nil {
		t.Fatalf("Allow() error = %v, want nil", err)
	}
	if !decision.Allowed {
		t.Error("Allow() with Redis unreachable and FailOpen=true = blocked, want allowed")
	}
}
