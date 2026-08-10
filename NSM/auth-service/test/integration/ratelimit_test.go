//go:build integration

package integration

import (
	"context"
	"os"
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
