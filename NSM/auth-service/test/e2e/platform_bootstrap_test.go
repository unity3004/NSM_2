//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const platformAdminRoleID = "00000000-0000-4000-9000-000000000001"

// resetPlatformUninitialized puts the shared test database back into a
// genuinely "fresh installation" state before a bootstrap test runs: finds
// whichever users currently hold the seeded Platform Administrator role
// (via the role grant, not any assumption about which organization
// bootstrap attached them to — this suite's own newE2EEnv already loads a
// pre-existing fixture organization, and BootstrapService correctly
// attaches to it rather than creating a redundant second one; a query
// that assumed a fresh "default"-slug org every time would be testing the
// wrong thing here), deletes those users (their role grants cascade-delete
// with them), and resets the platform_bootstrap singleton row to
// 'uninitialized'. Deliberately never touches the organizations table
// itself — reusing or not reusing an existing organization is
// BootstrapService's decision to make per call, not something a test
// reset should force either way.
//
// This is test-only, direct-to-database setup — the same category of
// thing loadFixtures already does — never something the application
// itself exposes a way to do (see the objective's own "bootstrap must
// permanently stop being available" and "administrative/deployment
// procedure" language: this helper *is* that out-of-band procedure, for
// test purposes).
func resetPlatformUninitialized(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx,
		`DELETE FROM users WHERE id IN (SELECT user_id FROM user_roles WHERE role_id = $1)`,
		platformAdminRoleID,
	); err != nil {
		t.Fatalf("resetPlatformUninitialized: delete administrators: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE platform_bootstrap SET status = 'uninitialized', initialized_by = NULL, initialized_at = NULL WHERE id = 1`,
	); err != nil {
		t.Fatalf("resetPlatformUninitialized: reset singleton row: %v", err)
	}
}

// countAdministrators reports how many users currently hold the seeded
// Platform Administrator role — the authoritative definition of "an
// administrator bootstrap created," independent of which organization
// they ended up in.
func countAdministrators(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM user_roles WHERE role_id = $1`, platformAdminRoleID,
	).Scan(&n); err != nil {
		t.Fatalf("count administrators: %v", err)
	}
	return n
}

func platformStatus(t *testing.T, client *http.Client, baseURL string) bool {
	t.Helper()
	res, body := doRequest(t, client, mustGet(t, baseURL+"/v1/platform/status"))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/platform/status: got %d; body=%s", res.StatusCode, body)
	}
	var parsed struct {
		Initialized bool `json:"initialized"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode platform status: %v", err)
	}
	return parsed.Initialized
}

func mustGet(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", url, err)
	}
	return req
}

// TEST 1 / TEST 12 (partial) / DATABASE TEST — a real fresh-install
// bootstrap: status starts false, the real POST succeeds, status flips to
// true, exactly one administrator exists with the seeded system role and
// a real "platform.initialized" audit event, and no plaintext password
// exists anywhere the response or the database could reveal one.
func TestPlatformBootstrap_FreshInstall_Succeeds(t *testing.T) {
	env := newE2EEnv(t)
	client := &http.Client{}
	resetPlatformUninitialized(t, env.DB)

	if platformStatus(t, client, env.Server.URL) {
		t.Fatalf("expected uninitialized after reset, got initialized=true")
	}

	email := fmt.Sprintf("bootstrap-admin-%s@example.test", uniqueSuffix(t))
	res, body := postJSON(t, client, env.Server.URL+"/v1/platform/bootstrap", map[string]any{
		"username": "bootstrap-admin",
		"email":    email,
		"password": "Bootstrap-Admin-Pw1!",
	}, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/platform/bootstrap: got %d, want 201; body=%s", res.StatusCode, body)
	}
	assertNoForbiddenFields(t, "bootstrap response", body)
	if strings.Contains(string(body), "Bootstrap-Admin-Pw1!") {
		t.Fatalf("bootstrap response leaked the plaintext password: %s", body)
	}

	if !platformStatus(t, client, env.Server.URL) {
		t.Fatalf("expected initialized=true after a successful bootstrap")
	}

	// --- direct database verification ---
	ctx := context.Background()
	if got := countAdministrators(t, env.DB); got != 1 {
		t.Fatalf("expected exactly 1 grant of the Platform Administrator role, got %d", got)
	}

	var auditCount int
	if err := env.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_logs WHERE action = 'platform.initialized' AND metadata->>'email' = $1`,
		strings.ToLower(email),
	).Scan(&auditCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("expected exactly 1 'platform.initialized' audit event for %s, got %d", email, auditCount)
	}

	var passwordHash string
	if err := env.DB.QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE email = $1`, strings.ToLower(email),
	).Scan(&passwordHash); err != nil {
		t.Fatalf("read password_hash: %v", err)
	}
	if passwordHash == "Bootstrap-Admin-Pw1!" || !strings.HasPrefix(passwordHash, "$argon2id$") {
		t.Fatalf("password_hash is not a real Argon2id hash: %q", passwordHash)
	}

	// Login with the real credentials must now work — the bootstrap
	// account is a fully real, usable account, not a placeholder. Every
	// real client always sends X-Organization-Id (see
	// organizationIDFromRequest in auth_handler.go); fixtureOrgID is what
	// FirstOrganizationID resolves to in this shared E2E environment,
	// which already has that fixture organization loaded.
	loginRes, loginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login", map[string]any{
		"email":    email,
		"password": "Bootstrap-Admin-Pw1!",
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login with the freshly bootstrapped administrator: got %d, want 200; body=%s", loginRes.StatusCode, loginBody)
	}
}

// TEST 3 / TEST 4 — after initialization, a second bootstrap attempt is
// rejected by the real backend, not merely hidden by the frontend.
func TestPlatformBootstrap_AlreadyInitialized_Rejected(t *testing.T) {
	env := newE2EEnv(t)
	client := &http.Client{}
	resetPlatformUninitialized(t, env.DB)

	first, firstBody := postJSON(t, client, env.Server.URL+"/v1/platform/bootstrap", map[string]any{
		"username": "first-admin",
		"email":    fmt.Sprintf("first-admin-%s@example.test", uniqueSuffix(t)),
		"password": "First-Admin-Pw1!",
	}, nil)
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first bootstrap: got %d, want 201; body=%s", first.StatusCode, firstBody)
	}

	second, secondBody := postJSON(t, client, env.Server.URL+"/v1/platform/bootstrap", map[string]any{
		"username": "second-admin",
		"email":    fmt.Sprintf("second-admin-%s@example.test", uniqueSuffix(t)),
		"password": "Second-Admin-Pw1!",
	}, nil)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second bootstrap after initialization: got %d, want 409; body=%s", second.StatusCode, secondBody)
	}
	// Must not confirm or deny anything about the first administrator.
	if strings.Contains(strings.ToLower(string(secondBody)), "first-admin") {
		t.Fatalf("rejection response leaked the existing administrator's identity: %s", secondBody)
	}

	if got := countAdministrators(t, env.DB); got != 1 {
		t.Fatalf("a rejected second bootstrap must not create a partial/second administrator; got %d", got)
	}
}

// TEST 5 — the actual race-condition test: many concurrent bootstrap
// requests against a genuinely uninitialized platform. Exactly one must
// create an administrator; every other must receive 409, never 201, and
// never a partial/corrupted state.
func TestPlatformBootstrap_ConcurrentRequests_ExactlyOneWins(t *testing.T) {
	env := newE2EEnv(t)
	resetPlatformUninitialized(t, env.DB)

	var orgCountBefore int
	if err := env.DB.QueryRowContext(context.Background(), `SELECT count(*) FROM organizations`).Scan(&orgCountBefore); err != nil {
		t.Fatalf("count organizations before: %v", err)
	}

	const concurrency = 10
	var created, conflicted, other int64
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := range concurrency {
		go func(i int) {
			defer wg.Done()
			client := &http.Client{}
			res, _ := postJSON(t, client, env.Server.URL+"/v1/platform/bootstrap", map[string]any{
				"username": fmt.Sprintf("race-admin-%d", i),
				"email":    fmt.Sprintf("race-admin-%d-%s@example.test", i, uniqueSuffix(t)),
				"password": "Race-Admin-Pw1!",
			}, nil)
			switch res.StatusCode {
			case http.StatusCreated:
				atomic.AddInt64(&created, 1)
			case http.StatusConflict:
				atomic.AddInt64(&conflicted, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}(i)
	}
	wg.Wait()

	if created != 1 {
		t.Fatalf("expected exactly 1 of %d concurrent bootstrap requests to succeed (201), got %d", concurrency, created)
	}
	if conflicted != concurrency-1 {
		t.Fatalf("expected the remaining %d requests to get 409, got %d (and %d unexpected other status codes)", concurrency-1, conflicted, other)
	}
	if other != 0 {
		t.Fatalf("expected zero unexpected status codes, got %d", other)
	}

	if got := countAdministrators(t, env.DB); got != 1 {
		t.Fatalf("expected exactly 1 administrator to exist after %d concurrent attempts, got %d", concurrency, got)
	}

	// However many organizations existed before this test (this suite's
	// fixture organization, typically exactly one), that count must be
	// unchanged afterward — FirstOrganizationID + a losing transaction's
	// rollback together mean concurrent racers must never each create
	// their own organization.
	var orgCountAfter int
	if err := env.DB.QueryRowContext(context.Background(), `SELECT count(*) FROM organizations`).Scan(&orgCountAfter); err != nil {
		t.Fatalf("count organizations: %v", err)
	}
	if orgCountAfter != orgCountBefore {
		t.Fatalf("organization count changed from %d to %d — concurrent bootstrap requests must not each create their own organization", orgCountBefore, orgCountAfter)
	}
}

// TEST 6 — a weak password is rejected by the platform's real password
// policy, the same one every other account is held to.
func TestPlatformBootstrap_WeakPassword_Rejected(t *testing.T) {
	env := newE2EEnv(t)
	client := &http.Client{}
	resetPlatformUninitialized(t, env.DB)

	res, body := postJSON(t, client, env.Server.URL+"/v1/platform/bootstrap", map[string]any{
		"username": "weak-pw-admin",
		"email":    fmt.Sprintf("weak-pw-admin-%s@example.test", uniqueSuffix(t)),
		"password": "short",
	}, nil)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("weak password bootstrap: got %d, want 422; body=%s", res.StatusCode, body)
	}

	if platformStatus(t, client, env.Server.URL) {
		t.Fatalf("a rejected (422) bootstrap attempt must not leave the platform initialized")
	}
}
