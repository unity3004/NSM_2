//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/acme/auth-service/internal/dto"
)

// newSecretsE2EEnv is newE2EEnv plus a freshly generated, per-test random
// AES-256 key exported as AUTH_SECRETS_DEV_MASTER_KEY (t.Setenv, so it's
// automatically restored after this test) — config.Load (called inside
// newE2EEnv) only wires the Secrets Engine and registers /v1/secrets at
// all when that variable is set (see setup_test.go's own comment). Each
// call gets its own random key: every secrets e2e test operates on its
// own uniquely-suffixed paths (see uniqueSuffix), so there is no
// cross-test decryption to keep a shared key for.
//
// Also disables rate limiting (AUTH_RATE_LIMIT_ENABLED=false) for this
// test's own httptest.Server instance only — t.Setenv is per-test, so this
// has no effect on any other test's own newE2EEnv call, including
// platform_bootstrap_test.go's own dedicated rate-limit coverage. This
// file needs POST /v1/platform/bootstrap purely as setup (to obtain an
// authorized actor), not as something it's testing the rate-limit
// behavior of — and platform_bootstrap_test.go's own
// TestPlatformBootstrap_ConcurrentRequests_ExactlyOneWins alone fires 10
// concurrent bootstrap attempts from the same IP, which by itself already
// exhausts BootstrapRateLimitConfig's default 5-per-hour budget before
// this file's own bootstrap call ever gets a turn when the whole e2e
// suite runs together — not a bug in the limiter (it is correctly
// protecting a genuinely sensitive endpoint), just an unrelated collision
// this file's setup must not depend on avoiding.
func newSecretsE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	t.Setenv("AUTH_SECRETS_DEV_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("AUTH_RATE_LIMIT_ENABLED", "false")
	return newE2EEnv(t)
}

// doAuthed sends a JSON (or bodyless) request carrying a bearer token and
// any extra headers (e.g. If-Match) — the If-Match/PUT/DELETE-capable
// sibling of postJSON/getWithAuth (registration_login_protected_test.go),
// which don't support either. Always sets X-Organization-Id: fixtureOrgID
// — organizationIDFromRequest (auth_handler.go) reads this header
// directly on every request, the same way every other authenticated
// write in this test suite already sets it (see orgHeaders in
// registration_login_protected_test.go); it is never derived from the
// bearer token's own claims.
func doAuthed(t *testing.T, client *http.Client, method, url, accessToken string, body any, extraHeaders map[string]string) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("X-Organization-Id", fixtureOrgID)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return doRequest(t, client, req)
}

// bootstrapAdminAndLogin resets the platform to uninitialized, bootstraps
// a fresh administrator (who — per BootstrapService — is granted the
// seeded Platform Administrator role, which carries every secrets:*
// permission, migrations/000022 + 000025), logs in, and returns the
// admin's user ID and a real, verified access token. Registers a
// t.Cleanup that removes any secrets this test's admin created (and the
// admin itself) — necessary so a *later* bootstrap test's own
// resetPlatformUninitialized (which deletes every Platform-Administrator
// user) never hits secrets_created_by_fkey's ON DELETE RESTRICT the way
// an earlier version of this exact scenario did during Phase 3's own
// validation (see that phase's final report) — this test must not
// reintroduce that failure mode for suites that run after it.
func bootstrapAdminAndLogin(t *testing.T, env *e2eEnv) (adminID, accessToken string) {
	t.Helper()
	client := env.Server.Client()
	resetPlatformUninitialized(t, env.DB)

	email := fmt.Sprintf("secrets-e2e-admin-%s@example.test", uniqueSuffix(t))
	res, body := postJSON(t, client, env.Server.URL+"/v1/platform/bootstrap", map[string]any{
		"username": "secrets-e2e-admin",
		"email":    email,
		"password": "Secrets-E2e-Admin-Pw1!",
	}, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/platform/bootstrap: got %d, want 201; body=%s", res.StatusCode, body)
	}

	loginRes, loginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login",
		dto.LoginRequest{Email: email, Password: "Secrets-E2e-Admin-Pw1!"},
		map[string]string{"X-Organization-Id": fixtureOrgID})
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/auth/login (admin): got %d, want 200; body=%s", loginRes.StatusCode, loginBody)
	}
	var tok dto.TokenResponse
	if err := json.Unmarshal(loginBody, &tok); err != nil {
		t.Fatalf("decode TokenResponse: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("admin login: empty access token")
	}

	var id string
	if err := env.DB.QueryRow(`SELECT id FROM users WHERE email = $1`, strings.ToLower(email)).Scan(&id); err != nil {
		t.Fatalf("look up bootstrapped admin id: %v", err)
	}

	t.Cleanup(func() {
		if _, err := env.DB.Exec(`DELETE FROM secret_versions WHERE created_by = $1`, id); err != nil {
			t.Logf("cleanup: delete secret_versions for admin %s: %v", id, err)
		}
		if _, err := env.DB.Exec(`DELETE FROM secrets WHERE created_by = $1`, id); err != nil {
			t.Logf("cleanup: delete secrets for admin %s: %v", id, err)
		}
		if _, err := env.DB.Exec(`DELETE FROM users WHERE id = $1`, id); err != nil {
			t.Logf("cleanup: delete admin user %s: %v", id, err)
		}
	})

	return id, tok.AccessToken
}

// registerPlainUser registers a real user with zero role grants — an
// authenticated identity that holds none of secrets:create/read/update/
// delete/list, for the "authenticated but not authorized" (403) tests.
func registerPlainUser(t *testing.T, env *e2eEnv) (userID, accessToken string) {
	t.Helper()
	client := env.Server.Client()
	suffix := uniqueSuffix(t)
	email := fmt.Sprintf("secrets-e2e-plain-%s@example.test", suffix)
	orgHeaders := map[string]string{"X-Organization-Id": fixtureOrgID}

	res, body := postJSON(t, client, env.Server.URL+"/v1/auth/register",
		dto.RegisterRequest{Username: "secrets-e2e-plain-" + suffix, Email: email, Password: testPassword}, orgHeaders)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/auth/register: got %d, want 201; body=%s", res.StatusCode, body)
	}
	var reg dto.RegisterResponse
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatalf("decode RegisterResponse: %v", err)
	}
	t.Cleanup(func() {
		if _, err := env.DB.Exec(`DELETE FROM users WHERE id = $1`, reg.ID); err != nil {
			t.Logf("cleanup: delete plain user %s: %v", reg.ID, err)
		}
	})

	loginRes, loginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login",
		dto.LoginRequest{Email: email, Password: testPassword}, orgHeaders)
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/auth/login (plain user): got %d, want 200; body=%s", loginRes.StatusCode, loginBody)
	}
	var tok dto.TokenResponse
	if err := json.Unmarshal(loginBody, &tok); err != nil {
		t.Fatalf("decode TokenResponse: %v", err)
	}
	return reg.ID, tok.AccessToken
}

func auditCount(t *testing.T, env *e2eEnv, action, resourceID string) int {
	t.Helper()
	var n int
	if err := env.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action = $1 AND resource_id = $2`, action, resourceID).Scan(&n); err != nil {
		t.Fatalf("count audit_logs action=%q resource_id=%q: %v", action, resourceID, err)
	}
	return n
}

// --- 1. Unauthenticated request -> 401 ---

func TestSecretsE2E_Unauthenticated_Returns401(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/v1/secrets"},
		{http.MethodPost, "/v1/secrets"},
		{http.MethodGet, "/v1/secrets/prod/db"},
		{http.MethodPut, "/v1/secrets/prod/db"},
		{http.MethodDelete, "/v1/secrets/prod/db"},
	} {
		t.Run(req.method, func(t *testing.T) {
			res, body := doAuthed(t, client, req.method, env.Server.URL+req.path, "", nil, nil)
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s with no Authorization header: status = %d, want 401; body = %s", req.method, req.path, res.StatusCode, body)
			}
		})
	}
}

// --- 2. Authenticated user without permission -> 403 ---

func TestSecretsE2E_AuthenticatedWithoutPermission_Returns403(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, plainToken := registerPlainUser(t, env)

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/v1/secrets"},
		{http.MethodPost, "/v1/secrets"},
		{http.MethodGet, "/v1/secrets/prod/db"},
		{http.MethodPut, "/v1/secrets/prod/db"},
		{http.MethodDelete, "/v1/secrets/prod/db"},
	} {
		t.Run(req.method, func(t *testing.T) {
			res, body := doAuthed(t, client, req.method, env.Server.URL+req.path, plainToken, nil, nil)
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s as a user with no secrets:* grants: status = %d, want 403; body = %s", req.method, req.path, res.StatusCode, body)
			}
		})
	}
}

// TestSecretsE2E_AuthorizedOperations bootstraps exactly one administrator
// and reuses that one admin/token across every subtest below — deliberately,
// not for speed alone: POST /v1/platform/bootstrap shares one IP-scoped
// rate-limit budget (5 per hour by default — see
// config.BootstrapRateLimitConfig) with every other e2e test file that
// bootstraps (platform_bootstrap_test.go alone makes several calls, one of
// them 10 concurrent). Giving each of these six scenarios (items 3-17, and
// the task's own END-TO-END TEST) its own top-level bootstrap call —
// perfectly correct in isolation — reliably exhausted that shared budget
// the moment this suite ran alongside platform_bootstrap_test.go, turning
// every bootstrap after the fifth into a real 429 instead of the 201 the
// test expected. One bootstrap for this whole file's authorized-operation
// coverage fixes that without touching the rate limiter itself, which is
// correctly protecting a genuinely sensitive endpoint and shouldn't be
// loosened just to make a test suite's own call volume more convenient.
func TestSecretsE2E_AuthorizedOperations(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, token := bootstrapAdminAndLogin(t, env)

	t.Run("FullLifecycle", func(t *testing.T) {
		testSecretsFullLifecycle(t, env, client, token, adminID)
	})
	t.Run("DuplicateCreate_Returns409", func(t *testing.T) {
		testSecretsDuplicateCreate(t, env, client, token)
	})
	t.Run("PathTraversalRejected", func(t *testing.T) {
		testSecretsPathTraversalRejected(t, env, client, token)
	})
	t.Run("MalformedJSON_Rejected", func(t *testing.T) {
		testSecretsMalformedJSON(t, env, client, token)
	})
	t.Run("OversizedRequest_Rejected", func(t *testing.T) {
		testSecretsOversizedRequest(t, env, client, token)
	})
	t.Run("VersioningAndRollback", func(t *testing.T) {
		testSecretsVersioningAndRollback(t, env, client, token)
	})
}

// testSecretsFullLifecycle covers items 3-8, 10, 16, 17, and the task's own
// explicit END-TO-END TEST scenario in one real, ordered flow.
func testSecretsFullLifecycle(t *testing.T, env *e2eEnv, client *http.Client, token, adminID string) {
	path := "prod/" + uniqueSuffix(t) + "/db"

	original := map[string]string{"username": "app_user", "password": "SuperSecret", "host": "db.internal"}

	var createdVersion int

	// --- POST /v1/secrets -> verify success (item 3, 7) ---
	t.Run("Create", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", token,
			map[string]any{"path": path, "data": original}, nil)
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("POST /v1/secrets: status = %d, want 201; body = %s", res.StatusCode, body)
		}
		var got dto.SecretResponse
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode SecretResponse: %v", err)
		}
		if got.Path != path {
			t.Errorf("SecretResponse.Path = %q, want %q", got.Path, path)
		}
		if got.Version != 1 {
			t.Errorf("SecretResponse.Version = %d, want 1", got.Version)
		}
		createdVersion = got.Version

		// item 9: create's response never contains the plaintext values,
		// and never even carries a "data" field at all.
		lower := strings.ToLower(string(body))
		for _, v := range original {
			if strings.Contains(lower, strings.ToLower(v)) {
				t.Errorf("create response unexpectedly contains a plaintext value %q: %s", v, body)
			}
		}
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		if _, present := raw["data"]; present {
			t.Error(`create response unexpectedly has a "data" field — CreateSecret must return metadata only`)
		}

		// item 20: no key material or crypto metadata in the response.
		for _, forbidden := range []string{"key_id", "nonce", "ciphertext", "wrapped_dek", "auth_tag"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("create response unexpectedly contains %q", forbidden)
			}
		}
	})
	if t.Failed() {
		t.Fatal("create did not succeed; aborting dependent scenarios")
	}

	// --- Verify encrypted database record directly ---
	t.Run("VerifyEncryptedRecord", func(t *testing.T) {
		var ciphertext []byte
		var secretID string
		err := env.DB.QueryRow(`
			SELECT sv.ciphertext, sv.secret_id FROM secret_versions sv
			JOIN secrets s ON s.id = sv.secret_id
			WHERE s.path = $1 AND sv.version = 1`, path).Scan(&ciphertext, &secretID)
		if err != nil {
			t.Fatalf("reading raw secret_versions row: %v", err)
		}
		lower := strings.ToLower(string(ciphertext))
		for _, v := range original {
			if strings.Contains(lower, strings.ToLower(v)) {
				t.Errorf("raw ciphertext contains plaintext value %q — payload was not encrypted", v)
			}
		}
	})

	// --- GET /v1/secrets -> verify metadata only (items 7, 8) ---
	t.Run("ListMetadataOnly", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets", token, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/secrets: status = %d, want 200; body = %s", res.StatusCode, body)
		}
		var out struct {
			Data []dto.SecretResponse `json:"data"`
			Page dto.PageMeta         `json:"page"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode list response: %v", err)
		}
		found := false
		for _, s := range out.Data {
			if s.Path == path {
				found = true
			}
		}
		if !found {
			t.Errorf("list did not include the just-created secret %q", path)
		}
		lower := strings.ToLower(string(body))
		for _, v := range original {
			if strings.Contains(lower, strings.ToLower(v)) {
				t.Errorf("list response unexpectedly contains a plaintext value %q", v)
			}
		}
		for _, forbidden := range []string{"ciphertext", "key_id", "nonce", "wrapped_dek"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("list response unexpectedly contains %q", forbidden)
			}
		}
	})

	// --- GET /v1/secrets/{path} -> verify authorized retrieval (item 4, 10) ---
	t.Run("Read", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/secrets/%s: status = %d, want 200; body = %s", path, res.StatusCode, body)
		}
		var got dto.SecretValueResponse
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode SecretValueResponse: %v", err)
		}
		if got.Version != 1 {
			t.Errorf("Read version = %d, want 1", got.Version)
		}
		for k, want := range original {
			if got.Data[k] != want {
				t.Errorf("Read Data[%q] = %q, want %q", k, got.Data[k], want)
			}
		}
		for _, forbidden := range []string{"key_id", "nonce", "ciphertext", "wrapped_dek", "auth_tag"} {
			if strings.Contains(strings.ToLower(string(body)), forbidden) {
				t.Errorf("read response unexpectedly contains %q", forbidden)
			}
		}
	})

	// --- PUT /v1/secrets/{path} -> verify new version (item 5) ---
	rotated := map[string]string{"username": "app_user", "password": "RotatedSecret", "host": "db.internal"}
	t.Run("Update", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secrets/"+path, token,
			map[string]any{"data": rotated}, map[string]string{"If-Match": fmt.Sprintf(`"%d"`, createdVersion)})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("PUT /v1/secrets/%s: status = %d, want 200; body = %s", path, res.StatusCode, body)
		}
		var got dto.SecretResponse
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode SecretResponse: %v", err)
		}
		if got.Version != 2 {
			t.Errorf("Update Version = %d, want 2", got.Version)
		}
	})
	if t.Failed() {
		t.Fatal("update did not succeed; aborting dependent scenarios")
	}

	// --- GET ?version=1 -> verify old version unchanged ---
	t.Run("ReadVersion1Unchanged", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path+"?version=1", token, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/secrets/%s?version=1: status = %d, want 200; body = %s", path, res.StatusCode, body)
		}
		var got dto.SecretValueResponse
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode SecretValueResponse: %v", err)
		}
		if got.Version != 1 {
			t.Errorf("version=1 request returned Version %d, want 1", got.Version)
		}
		if got.Data["password"] != "SuperSecret" {
			t.Errorf("version 1 password = %q, want the original %q — must be unaffected by the update", got.Data["password"], "SuperSecret")
		}
	})

	// --- GET current -> reflects version 2 ---
	t.Run("ReadCurrentIsVersion2", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/secrets/%s: status = %d; body = %s", path, res.StatusCode, body)
		}
		var got dto.SecretValueResponse
		_ = json.Unmarshal(body, &got)
		if got.Version != 2 || got.Data["password"] != "RotatedSecret" {
			t.Errorf("current read = version %d, password %q, want version 2 with the rotated password", got.Version, got.Data["password"])
		}
	})

	// --- version conflict: stale If-Match -> 409 (item 16) ---
	t.Run("VersionConflict", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secrets/"+path, token,
			map[string]any{"data": map[string]string{"password": "should-not-apply"}}, map[string]string{"If-Match": `"1"`})
		if res.StatusCode != http.StatusConflict {
			t.Fatalf("PUT with stale If-Match: status = %d, want 409; body = %s", res.StatusCode, body)
		}
		var errBody dto.Error
		if err := json.Unmarshal(body, &errBody); err != nil {
			t.Fatalf("decode error response: %v", err)
		}
		if errBody.Error.Code != dto.CodeVersionConflict {
			t.Errorf("error code = %q, want %q", errBody.Error.Code, dto.CodeVersionConflict)
		}
	})

	// --- DELETE /v1/secrets/{path} -> verify normal retrieval fails afterward (item 6, 17) ---
	t.Run("DeleteThenReadFails", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE /v1/secrets/%s: status = %d, want 204; body = %s", path, res.StatusCode, body)
		}

		res2, body2 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
		if res2.StatusCode != http.StatusNotFound {
			t.Errorf("GET after delete: status = %d, want 404; body = %s", res2.StatusCode, body2)
		}
	})

	// --- item 18: audit events occur exactly once per API call — never
	// zero (the handler failing to trigger one) and never duplicated (the
	// handler and the service both recording one for the same call).
	// "Exactly once" is per call, not per test: this test flow makes
	// three separate, legitimate GETs (Read, ReadVersion1Unchanged,
	// ReadCurrentIsVersion2), so three secret.read rows is the correct
	// count, not a bug — one create, one successful update (the rejected
	// VersionConflict attempt correctly produces zero additional rows, so
	// updated stays at exactly 1), and one delete each happened exactly
	// once. ---
	t.Run("AuditExactlyOnce", func(t *testing.T) {
		var secretID string
		if err := env.DB.QueryRow(`SELECT id FROM secrets WHERE path = $1`, path).Scan(&secretID); err != nil {
			t.Fatalf("look up secret id: %v", err)
		}
		// secret.read = 2 (Read, ReadCurrentIsVersion2 — both current-version
		// reads), not 3: ReadVersion1Unchanged explicitly names a historical
		// version (?version=1), which the Secret Versioning phase now
		// audits as the more precise secret.version_accessed instead — see
		// SecretService.GetSecret's own doc comment on that split. The
		// total "a read happened" count (2 + 1) is unchanged from before
		// that phase; only the label on the explicit-version one is.
		wantCounts := map[string]int{
			"secret.created":          1,
			"secret.read":             2,
			"secret.version_accessed": 1,
			"secret.updated":          1,
			"secret.deleted":          1,
		}
		for action, want := range wantCounts {
			if n := auditCount(t, env, action, secretID); n != want {
				t.Errorf("audit_logs has %d rows for action=%q resource_id=%q, want exactly %d", n, action, secretID, want)
			}
		}
	})

	// --- items 9, 19, 20: audit metadata never contains plaintext,
	// tokens, or key material ---
	t.Run("AuditNeverLeaksSensitiveData", func(t *testing.T) {
		var secretID string
		if err := env.DB.QueryRow(`SELECT id FROM secrets WHERE path = $1`, path).Scan(&secretID); err != nil {
			t.Fatalf("look up secret id: %v", err)
		}
		rows, err := env.DB.Query(`SELECT metadata::text FROM audit_logs WHERE resource_id = $1`, secretID)
		if err != nil {
			t.Fatalf("query audit metadata: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var metadata string
			if err := rows.Scan(&metadata); err != nil {
				t.Fatalf("scan audit metadata: %v", err)
			}
			lower := strings.ToLower(metadata)
			for _, v := range original {
				if strings.Contains(lower, strings.ToLower(v)) {
					t.Errorf("audit_logs.metadata contains plaintext value %q: %s", v, metadata)
				}
			}
			for _, v := range rotated {
				if strings.Contains(lower, strings.ToLower(v)) {
					t.Errorf("audit_logs.metadata contains plaintext value %q: %s", v, metadata)
				}
			}
			if strings.Contains(lower, strings.ToLower(token)) {
				t.Error("audit_logs.metadata contains the raw access token")
			}
			for _, forbidden := range []string{"key_id", "nonce", "ciphertext", "wrapped_dek"} {
				if strings.Contains(lower, forbidden) {
					t.Errorf("audit_logs.metadata unexpectedly contains %q", forbidden)
				}
			}
		}
	})

	_ = adminID
}

// --- 15. Duplicate secret creation handled correctly ---

func testSecretsDuplicateCreate(t *testing.T, env *e2eEnv, client *http.Client, token string) {
	path := "prod/" + uniqueSuffix(t) + "/dup"

	res1, body1 := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", token,
		map[string]any{"path": path, "data": map[string]string{"k": "v"}}, nil)
	if res1.StatusCode != http.StatusCreated {
		t.Fatalf("first POST /v1/secrets: status = %d, want 201; body = %s", res1.StatusCode, body1)
	}

	res2, body2 := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", token,
		map[string]any{"path": path, "data": map[string]string{"k": "v2"}}, nil)
	if res2.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate POST /v1/secrets: status = %d, want 409; body = %s", res2.StatusCode, body2)
	}
}

// --- 11 & 12. Invalid path / path traversal rejected ---

func testSecretsPathTraversalRejected(t *testing.T, env *e2eEnv, client *http.Client, token string) {
	// A literal ".." segment reaching the handler at all (whether via
	// net/http.ServeMux's own path cleaning/redirect, or via
	// SecretService's own util.ValidateSecretPath) must never resolve to
	// a 200 with secret data — this is the end-to-end proof that
	// secretHandler.get's own doc comment on path handling holds for a
	// real HTTP client, not just for r.PathValue in isolation.
	for _, path := range []string{
		"/v1/secrets/../etc/passwd",
		"/v1/secrets/prod/../../etc/passwd",
		"/v1/secrets/prod%2F..%2F..%2Fetc%2Fpasswd",
	} {
		t.Run(path, func(t *testing.T) {
			res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+path, token, nil, nil)
			if res.StatusCode == http.StatusOK {
				t.Errorf("GET %s unexpectedly succeeded (200); body = %s", path, body)
			}
		})
	}
}

// --- 13. Malformed JSON rejected (real HTTP round trip) ---

func testSecretsMalformedJSON(t *testing.T, env *e2eEnv, client *http.Client, token string) {
	req, err := http.NewRequest(http.MethodPost, env.Server.URL+"/v1/secrets", strings.NewReader(`{"path": "prod/db", "data": `))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, body := doRequest(t, client, req)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", res.StatusCode, body)
	}
}

// --- 14. Oversized request rejected (real HTTP round trip) ---

func testSecretsOversizedRequest(t *testing.T, env *e2eEnv, client *http.Client, token string) {
	huge := strings.Repeat("A", 512*1024) // well past the 256 KiB cap
	req, err := http.NewRequest(http.MethodPost, env.Server.URL+"/v1/secrets",
		strings.NewReader(`{"path": "prod/db", "data": {"value": "`+huge+`"}}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, body := doRequest(t, client, req)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body length = %d", res.StatusCode, len(body))
	}
}

// testSecretsVersioningAndRollback is the Secret Versioning phase's own
// full worked example, against a real router and a real Postgres
// database: create (version 1 = password-one), update twice (version 2 =
// password-two, version 3 = password-three), list the version history,
// retrieve version 1 explicitly, roll back to it (creating version 4 =
// password-one, never touching 1-3), verify every version's audit trail,
// verify no plaintext ever reached the database, and verify a rollback
// racing an ordinary update against the same real database row cannot
// both land (this task's own "add an integration test" requirement for
// concurrency, item 14 — TestSecretService_RollbackSecret_ConcurrentWithUpdate_OnlyOneWins
// already covers the identical scenario against the in-memory fake; this
// is the same guarantee proven against Postgres's own row lock).
func testSecretsVersioningAndRollback(t *testing.T, env *e2eEnv, client *http.Client, token string) {
	path := "vaultis/demo/" + uniqueSuffix(t) + "/database"
	v1, v2, v3 := "password-one", "password-two", "password-three"

	// --- Create -> version 1 ---
	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", token,
		map[string]any{"path": path, "data": map[string]string{"password": v1}}, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/secrets: status = %d, want 201; body = %s", res.StatusCode, body)
	}

	// --- Update -> version 2, Update -> version 3 ---
	res, body = doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secrets/"+path, token,
		map[string]any{"data": map[string]string{"password": v2}}, map[string]string{"If-Match": `"1"`})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PUT (v2): status = %d, want 200; body = %s", res.StatusCode, body)
	}
	res, body = doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secrets/"+path, token,
		map[string]any{"data": map[string]string{"password": v3}}, map[string]string{"If-Match": `"2"`})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PUT (v3): status = %d, want 200; body = %s", res.StatusCode, body)
	}

	// --- Database plaintext verification (item 21): none of the three
	// plaintext values may appear anywhere in secret_versions' raw bytes. ---
	var secretID string
	if err := env.DB.QueryRow(`SELECT id FROM secrets WHERE path = $1`, path).Scan(&secretID); err != nil {
		t.Fatalf("look up secret id: %v", err)
	}
	rows, err := env.DB.Query(`SELECT version, ciphertext FROM secret_versions WHERE secret_id = $1 ORDER BY version`, secretID)
	if err != nil {
		t.Fatalf("query secret_versions: %v", err)
	}
	var rawVersions int
	for rows.Next() {
		var version int
		var ciphertext []byte
		if err := rows.Scan(&version, &ciphertext); err != nil {
			t.Fatalf("scan secret_versions row: %v", err)
		}
		rawVersions++
		lower := strings.ToLower(string(ciphertext))
		for _, plaintext := range []string{v1, v2, v3} {
			if strings.Contains(lower, strings.ToLower(plaintext)) {
				t.Errorf("secret_versions row (version %d) ciphertext contains plaintext %q in the clear", version, plaintext)
			}
		}
	}
	rows.Close()
	if rawVersions != 3 {
		t.Fatalf("secret_versions row count = %d, want 3 before rollback", rawVersions)
	}

	// --- List versions (item 8): metadata only, newest first, current flagged ---
	res, body = doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path+"?versions=true", token, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET ?versions=true: status = %d, want 200; body = %s", res.StatusCode, body)
	}
	var versionList struct {
		Data []dto.SecretVersionResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &versionList); err != nil {
		t.Fatalf("decode version list: %v", err)
	}
	if len(versionList.Data) != 3 {
		t.Fatalf("version list length = %d, want 3", len(versionList.Data))
	}
	if versionList.Data[0].Version != 3 || !versionList.Data[0].Current {
		t.Errorf("version list[0] = %+v, want version 3, current=true (newest first)", versionList.Data[0])
	}
	lowerVersionList := strings.ToLower(string(body))
	for _, plaintext := range []string{v1, v2, v3} {
		if strings.Contains(lowerVersionList, strings.ToLower(plaintext)) {
			t.Errorf("version list response unexpectedly contains plaintext %q: %s", plaintext, body)
		}
	}

	// --- Retrieve version 1 explicitly (item 7) ---
	res, body = doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path+"?version=1", token, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET ?version=1: status = %d, want 200; body = %s", res.StatusCode, body)
	}
	var v1Value dto.SecretValueResponse
	if err := json.Unmarshal(body, &v1Value); err != nil {
		t.Fatalf("decode version 1 value: %v", err)
	}
	if v1Value.Data["password"] != v1 {
		t.Errorf("version 1 password = %q, want %q", v1Value.Data["password"], v1)
	}

	// --- Rollback to version 1 (items 9-11): creates version 4, never
	// deletes 1-3. Requires the current version via If-Match, exactly like
	// update (see secret_handler.go's rollback). ---
	res, body = doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets/rollback", token,
		map[string]any{"path": path, "version": 1}, map[string]string{"If-Match": `"3"`})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/secrets/rollback: status = %d, want 200; body = %s", res.StatusCode, body)
	}
	var rolledBack dto.SecretResponse
	if err := json.Unmarshal(body, &rolledBack); err != nil {
		t.Fatalf("decode rollback SecretResponse: %v", err)
	}
	if rolledBack.Version != 4 {
		t.Fatalf("rollback response Version = %d, want 4", rolledBack.Version)
	}
	if strings.Contains(strings.ToLower(string(body)), strings.ToLower(v1)) {
		t.Errorf("rollback response unexpectedly contains plaintext: %s", body)
	}

	// --- Versions 1, 2, 3 remain intact; version 4 == version 1's value and is current ---
	for version, want := range map[int]string{1: v1, 2: v2, 3: v3, 4: v1} {
		res, body := doAuthed(t, client, http.MethodGet, fmt.Sprintf("%s/v1/secrets/%s?version=%d", env.Server.URL, path, version), token, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET ?version=%d after rollback: status = %d, want 200; body = %s", version, res.StatusCode, body)
		}
		var val dto.SecretValueResponse
		if err := json.Unmarshal(body, &val); err != nil {
			t.Fatalf("decode version %d value: %v", version, err)
		}
		if val.Data["password"] != want {
			t.Errorf("version %d password = %q, want %q — rollback must not mutate existing versions", version, val.Data["password"], want)
		}
	}
	res, body = doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET (current) after rollback: status = %d, want 200; body = %s", res.StatusCode, body)
	}
	var current dto.SecretValueResponse
	if err := json.Unmarshal(body, &current); err != nil {
		t.Fatalf("decode current value: %v", err)
	}
	if current.Version != 4 || current.Data["password"] != v1 {
		t.Errorf("current value = %+v, want version 4 with password %q", current, v1)
	}

	// --- Rollback-created ciphertext is freshly sealed, never the raw
	// version-1 ciphertext copied verbatim (item 16: independent encryption
	// per version), and still contains no plaintext ---
	var v1Ciphertext, v4Ciphertext []byte
	if err := env.DB.QueryRow(`SELECT ciphertext FROM secret_versions WHERE secret_id = $1 AND version = 1`, secretID).Scan(&v1Ciphertext); err != nil {
		t.Fatalf("read version 1 ciphertext: %v", err)
	}
	if err := env.DB.QueryRow(`SELECT ciphertext FROM secret_versions WHERE secret_id = $1 AND version = 4`, secretID).Scan(&v4Ciphertext); err != nil {
		t.Fatalf("read version 4 ciphertext: %v", err)
	}
	if string(v1Ciphertext) == string(v4Ciphertext) {
		t.Error("rollback stored version 1's ciphertext verbatim as version 4 — every version must be independently encrypted")
	}
	if strings.Contains(strings.ToLower(string(v4Ciphertext)), strings.ToLower(v1)) {
		t.Error("version 4's ciphertext contains the plaintext password in the clear")
	}

	// --- Audit events (item 18): version_accessed for the explicit-version
	// read, version_rollback for the rollback, both attributed to this
	// secret's ID, neither ever carrying plaintext. ---
	if n := auditCount(t, env, "secret.version_accessed", secretID); n < 1 {
		t.Errorf("secret.version_accessed audit count for secret %s = %d, want >= 1", secretID, n)
	}
	if n := auditCount(t, env, "secret.version_rollback", secretID); n != 1 {
		t.Errorf("secret.version_rollback audit count for secret %s = %d, want 1", secretID, n)
	}
	var auditMetadata []byte
	if err := env.DB.QueryRow(
		`SELECT metadata FROM audit_logs WHERE action = 'secret.version_rollback' AND resource_id = $1`, secretID,
	).Scan(&auditMetadata); err != nil {
		t.Fatalf("read secret.version_rollback audit metadata: %v", err)
	}
	lowerMetadata := strings.ToLower(string(auditMetadata))
	for _, plaintext := range []string{v1, v2, v3} {
		if strings.Contains(lowerMetadata, strings.ToLower(plaintext)) {
			t.Errorf("secret.version_rollback audit metadata unexpectedly contains plaintext %q: %s", plaintext, auditMetadata)
		}
	}

	// --- Concurrency (item 14, and this task's own explicit "add an
	// integration test" requirement): a rollback and an ordinary update,
	// both believing version 4 is current, fired concurrently against the
	// same real Postgres row. Exactly one may succeed; the other must see
	// entity.ErrVersionConflict (409), never a silently-lost update and
	// never two rows both claiming version 5. ---
	t.Run("ConcurrentRollbackAndUpdate_OnlyOneWins", func(t *testing.T) {
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			res, _ := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets/rollback", token,
				map[string]any{"path": path, "version": 2}, map[string]string{"If-Match": `"4"`})
			statuses[0] = res.StatusCode
		}()
		go func() {
			defer wg.Done()
			res, _ := doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secrets/"+path, token,
				map[string]any{"data": map[string]string{"password": "password-concurrent"}}, map[string]string{"If-Match": `"4"`})
			statuses[1] = res.StatusCode
		}()
		wg.Wait()

		successes, conflicts := 0, 0
		for _, code := range statuses {
			switch code {
			case http.StatusOK:
				successes++
			case http.StatusConflict:
				conflicts++
			default:
				t.Errorf("unexpected status %d (want 200 or 409)", code)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Errorf("successes=%d conflicts=%d, want exactly 1 of each — a rollback racing an update must not both land as version 5", successes, conflicts)
		}

		var finalVersion int
		if err := env.DB.QueryRow(`SELECT current_version FROM secrets WHERE id = $1`, secretID).Scan(&finalVersion); err != nil {
			t.Fatalf("read final current_version: %v", err)
		}
		if finalVersion != 5 {
			t.Errorf("final current_version = %d, want 5 (exactly one of the two racing writers)", finalVersion)
		}
		var totalVersions int
		if err := env.DB.QueryRow(`SELECT count(*) FROM secret_versions WHERE secret_id = $1`, secretID).Scan(&totalVersions); err != nil {
			t.Fatalf("count secret_versions: %v", err)
		}
		if totalVersions != 5 {
			t.Errorf("secret_versions row count = %d, want exactly 5 — never two competing version-5 rows", totalVersions)
		}
	})
}
