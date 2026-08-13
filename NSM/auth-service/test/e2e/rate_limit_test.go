//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/acme/auth-service/internal/dto"
)

// newRateLimitE2EEnv is newE2EEnv with rate limiting explicitly enabled
// (unlike newSecretsE2EEnv's own default of disabling it — this file is
// specifically testing the rate limiter, so it must be on) plus a fresh
// per-test secrets master key, the same "own random key per test" reasoning
// newSecretsE2EEnv's own doc comment gives. extraEnv lets each test dial in
// just the one or two category limits it actually exercises — every
// category this file doesn't touch keeps its real configs.go default, the
// same "override only what the test needs" discipline
// TestAPILimiter_FailurePostureIsPerCategory (internal/ratelimit) already
// follows at the unit level.
//
// Enabling AUTH_RATE_LIMIT_ENABLED=true means this env also needs a real,
// reachable Redis — same as every other e2e env that turns rate limiting
// on (see platform_bootstrap_test.go's own concurrent-bootstrap coverage,
// which relies on the same default-enabled rate limiting this env
// restores). newE2EEnv's own doc comment already documents why that's a
// hard t.Fatalf, never a second skip, once AUTH_JWT_SIGNING_KEY is set.
func newRateLimitE2EEnv(t *testing.T, extraEnv map[string]string) *e2eEnv {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	t.Setenv("AUTH_SECRETS_DEV_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("AUTH_RATE_LIMIT_ENABLED", "true")
	for k, v := range extraEnv {
		t.Setenv(k, v)
	}
	return newE2EEnv(t)
}

// rateLimitAuditCount counts rate_limit.exceeded audit entries for a given
// actor — recordRateLimitExceeded (internal/middleware/ratelimit.go) never
// sets ResourceID (only ResourceType, the category), so this queries
// directly rather than reusing secrets_test.go's own resource_id-keyed
// auditCount helper.
func rateLimitAuditCount(t *testing.T, env *e2eEnv, actorID string) int {
	t.Helper()
	var n int
	if err := env.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action = 'rate_limit.exceeded' AND actor_id = $1`, actorID).Scan(&n); err != nil {
		t.Fatalf("count rate_limit.exceeded audit entries for actor %q: %v", actorID, err)
	}
	return n
}

// --- secrets-read: threshold, 429 shape, audit trail, no internal leakage ---

func TestRateLimitE2E_SecretsRead_EnforcedWithAuditTrailAndSafeResponse(t *testing.T) {
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_RATE_LIMIT_API_SECRETS_READ_USER_LIMIT":  "3",
		"AUTH_RATE_LIMIT_API_SECRETS_READ_USER_WINDOW": "1m",
	})
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)

	for i := 0; i < 3; i++ {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets", adminToken, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("request %d: GET /v1/secrets status = %d, want 200; body=%s", i+1, res.StatusCode, body)
		}
	}

	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets", adminToken, nil, nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 4: status = %d, want 429; body=%s", res.StatusCode, body)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Error("429 response is missing a Retry-After header")
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "RATE_LIMITED") {
		t.Errorf("429 body missing RATE_LIMITED error code: %s", bodyStr)
	}
	for _, leak := range []string{"redis", "Redis", "ratelimit:", "TTL", "INCR", "Lua"} {
		if strings.Contains(bodyStr, leak) {
			t.Errorf("429 response body leaks internal detail %q: %s", leak, bodyStr)
		}
	}

	if n := rateLimitAuditCount(t, env, adminID); n != 1 {
		t.Errorf("rate_limit.exceeded audit entries for the admin = %d, want exactly 1 (fires once on the transition into throttling, not once per request)", n)
	}

	// A second, still-blocked request must not add a second audit entry —
	// the objective's own "do not create an audit event for every harmless
	// request" requirement, proven end-to-end this time.
	if res2, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets", adminToken, nil, nil); res2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 5: status = %d, want 429", res2.StatusCode)
	}
	if n := rateLimitAuditCount(t, env, adminID); n != 1 {
		t.Errorf("rate_limit.exceeded audit entries after a second blocked request = %d, want still exactly 1", n)
	}
}

// --- secrets-write: independent counter from secrets-read ---

func TestRateLimitE2E_SecretsWrite_IndependentFromSecretsRead(t *testing.T) {
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_RATE_LIMIT_API_SECRETS_WRITE_USER_LIMIT":  "2",
		"AUTH_RATE_LIMIT_API_SECRETS_WRITE_USER_WINDOW": "1m",
	})
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	for i := 0; i < 2; i++ {
		path := fmt.Sprintf("dev/%s/secret-%d", suffix, i)
		res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
			map[string]any{"path": path, "data": map[string]string{"k": "v"}}, nil)
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("create %d: status = %d, want 201; body=%s", i+1, res.StatusCode, body)
		}
	}

	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
		map[string]any{"path": fmt.Sprintf("dev/%s/secret-2", suffix), "data": map[string]string{"k": "v"}}, nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("create 3: status = %d, want 429; body=%s", res.StatusCode, body)
	}

	// secrets-read has its own, much larger default budget and must be
	// completely unaffected by secrets-write being throttled.
	readRes, readBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets", adminToken, nil, nil)
	if readRes.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/secrets after secrets-write was throttled: status = %d, want 200; body=%s", readRes.StatusCode, readBody)
	}
}

// --- policy-admin ---

func TestRateLimitE2E_PolicyAdminRateLimit_Enforced(t *testing.T) {
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_RATE_LIMIT_API_POLICY_ADMIN_USER_LIMIT":  "2",
		"AUTH_RATE_LIMIT_API_POLICY_ADMIN_USER_WINDOW": "1m",
	})
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	for i := 0; i < 2; i++ {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secret-policies", adminToken, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body=%s", i+1, res.StatusCode, body)
		}
	}
	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secret-policies", adminToken, nil, nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 3: status = %d, want 429; body=%s", res.StatusCode, body)
	}
}

// --- user-admin ---

func TestRateLimitE2E_UserAdminRateLimit_Enforced(t *testing.T) {
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_RATE_LIMIT_API_USER_ADMIN_USER_LIMIT":  "2",
		"AUTH_RATE_LIMIT_API_USER_ADMIN_USER_WINDOW": "1m",
	})
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	for i := 0; i < 2; i++ {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/users", adminToken, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body=%s", i+1, res.StatusCode, body)
		}
	}
	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/users", adminToken, nil, nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 3: status = %d, want 429; body=%s", res.StatusCode, body)
	}
}

// --- audit-read: never allow unlimited audit retrieval ---

func TestRateLimitE2E_AuditReadRateLimit_Enforced(t *testing.T) {
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_RATE_LIMIT_API_AUDIT_READ_USER_LIMIT":  "2",
		"AUTH_RATE_LIMIT_API_AUDIT_READ_USER_WINDOW": "1m",
	})
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	for i := 0; i < 2; i++ {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/audit-logs?limit=1", adminToken, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body=%s", i+1, res.StatusCode, body)
		}
	}
	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/audit-logs?limit=1", adminToken, nil, nil)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 3: status = %d, want 429; body=%s", res.StatusCode, body)
	}
}

// --- auth-register: IP identity, spoofing resistance ---

// TestRateLimitE2E_AuthRegister_SpoofedForwardedForDoesNotBypass proves the
// objective's own "avoid allowing an attacker to bypass protection simply
// by rotating IP addresses [via spoofed headers]" requirement end-to-end:
// with no trusted proxies configured (the default — see
// util.ResolveClientIP's own doc comment), X-Forwarded-For is never
// trusted, so every registration attempt is counted against the same real
// TCP peer address no matter what header value an attacker sends.
func TestRateLimitE2E_AuthRegister_SpoofedForwardedForDoesNotBypass(t *testing.T) {
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_RATE_LIMIT_API_AUTH_REGISTER_IP_LIMIT":  "3",
		"AUTH_RATE_LIMIT_API_AUTH_REGISTER_IP_WINDOW": "1h",
	})
	client := env.Server.Client()

	postRegister := func(spoofedIP string) (*http.Response, []byte) {
		suffix := uniqueSuffix(t)
		return doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/auth/register", "",
			dto.RegisterRequest{
				Username: "rl-spoof-" + suffix,
				Email:    fmt.Sprintf("rl-spoof-%s@example.test", suffix),
				Password: testPassword,
			},
			map[string]string{"X-Organization-Id": fixtureOrgID, "X-Forwarded-For": spoofedIP})
	}

	spoofedIPs := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	for i, ip := range spoofedIPs {
		res, body := postRegister(ip)
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("registration %d (X-Forwarded-For: %s): status = %d, want 201; body=%s", i+1, ip, res.StatusCode, body)
		}
	}

	// A 4th registration, with yet another spoofed IP, must still be
	// blocked — every attempt actually came from the same real peer.
	res, body := postRegister("198.51.100.4")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("registration 4 (a new spoofed X-Forwarded-For): status = %d, want 429 — spoofing the header must not reset the limit; body=%s", res.StatusCode, body)
	}
}

// TestRateLimitE2E_AuthRegister_TrustedProxy_HonorsForwardedFor is the
// other half of the same requirement: when the deployment explicitly
// configures the direct peer as a trusted reverse proxy (AUTH_SERVER_
// TRUSTED_PROXIES — see util.SetTrustedProxies's own doc comment), the
// application correctly attributes distinct rate-limit identities to
// distinct X-Forwarded-For values, because that's the genuinely correct
// behavior when a real proxy sits in front of it.
func TestRateLimitE2E_AuthRegister_TrustedProxy_HonorsForwardedFor(t *testing.T) {
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_SERVER_TRUSTED_PROXIES":                 "127.0.0.1",
		"AUTH_RATE_LIMIT_API_AUTH_REGISTER_IP_LIMIT":  "1",
		"AUTH_RATE_LIMIT_API_AUTH_REGISTER_IP_WINDOW": "1h",
	})
	client := env.Server.Client()

	postRegister := func(spoofedIP string) (*http.Response, []byte) {
		suffix := uniqueSuffix(t)
		return doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/auth/register", "",
			dto.RegisterRequest{
				Username: "rl-trusted-" + suffix,
				Email:    fmt.Sprintf("rl-trusted-%s@example.test", suffix),
				Password: testPassword,
			},
			map[string]string{"X-Organization-Id": fixtureOrgID, "X-Forwarded-For": spoofedIP})
	}

	res, body := postRegister("203.0.113.10")
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("registration from forwarded IP 203.0.113.10: status = %d, want 201; body=%s", res.StatusCode, body)
	}

	// The limit for that forwarded IP is 1 — a second registration
	// attributed to the same forwarded IP must be blocked.
	res, body = postRegister("203.0.113.10")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second registration from the same forwarded IP: status = %d, want 429; body=%s", res.StatusCode, body)
	}

	// A different forwarded IP is a different identity and gets its own,
	// independent budget.
	res, body = postRegister("203.0.113.20")
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("registration from a different forwarded IP 203.0.113.20: status = %d, want 201; body=%s", res.StatusCode, body)
	}
}

// --- concurrency: distributed correctness through the real HTTP stack ---

// TestRateLimitE2E_ConcurrentRequests_ExactlyLimitSucceed drives many
// concurrent HTTP requests (not direct Allow() calls — see
// internal/ratelimit's own fake- and Redis-backed concurrency tests for
// that layer) at the same authenticated identity and proves the real
// router+middleware+Redis stack lets through exactly the configured limit,
// never more, under real concurrent load.
func TestRateLimitE2E_ConcurrentRequests_ExactlyLimitSucceed(t *testing.T) {
	const limit = 10
	const attempts = 30
	env := newRateLimitE2EEnv(t, map[string]string{
		"AUTH_RATE_LIMIT_API_SECRETS_READ_USER_LIMIT":  "10",
		"AUTH_RATE_LIMIT_API_SECRETS_READ_USER_WINDOW": "1m",
	})
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	var wg sync.WaitGroup
	var mu sync.Mutex
	statusCounts := map[int]int{}

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets", adminToken, nil, nil)
			mu.Lock()
			statusCounts[res.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if statusCounts[http.StatusOK] != limit {
		t.Errorf("200 OK count = %d, want exactly %d (the configured limit) out of %d concurrent requests — a race would let more through", statusCounts[http.StatusOK], limit, attempts)
	}
	if statusCounts[http.StatusTooManyRequests] != attempts-limit {
		t.Errorf("429 count = %d, want exactly %d", statusCounts[http.StatusTooManyRequests], attempts-limit)
	}
	for status := range statusCounts {
		if status != http.StatusOK && status != http.StatusTooManyRequests {
			t.Errorf("unexpected status code %d appeared among the concurrent responses", status)
		}
	}
}
