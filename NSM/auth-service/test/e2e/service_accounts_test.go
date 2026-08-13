//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/dto"
)

// postWithAPIKey sends a JSON (or bodyless) POST authenticated via
// X-Api-Key rather than Authorization: Bearer — the machine-credential
// exchange endpoint's own security scheme (auth-service-openapi.yaml's
// apiKeyAuth), distinct from every other authenticated request in this
// test suite, which always goes through doAuthed's Bearer header instead.
func postWithAPIKey(t *testing.T, client *http.Client, url, apiKey string, body any) (*http.Response, []byte) {
	t.Helper()
	if body == nil {
		req, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if apiKey != "" {
			req.Header.Set("X-Api-Key", apiKey)
		}
		return doRequest(t, client, req)
	}
	res, raw := postJSON(t, client, url, body, map[string]string{"X-Api-Key": apiKey})
	return res, raw
}

// TestServiceAccountsE2E_PaymentServiceScenario is Sprint 5 Task 1's own
// worked example, run end-to-end through the real HTTP stack: create a
// service account, grant it a role carrying a path-scoped policy, issue
// it a credential, exchange that credential for a short-lived access
// token, and use that token against the real Secrets API — allowed inside
// its granted path, denied outside it. Then: disabling the service
// account blocks further authentication, and a revoked credential is
// rejected distinctly (401) from a disabled account (403), matching
// auth-service-openapi.yaml's own documented split for this endpoint.
func TestServiceAccountsE2E_PaymentServiceScenario(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	// --- create the service account ---
	desc := "payments integration"
	createRes, createBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/service-accounts", adminToken,
		map[string]any{"name": "payment-service-" + suffix, "description": desc}, nil)
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/service-accounts: status = %d, want 201; body = %s", createRes.StatusCode, createBody)
	}
	var sa dto.ServiceAccountResponse
	if err := json.Unmarshal(createBody, &sa); err != nil {
		t.Fatalf("decode ServiceAccountResponse: %v", err)
	}
	if sa.Status != "active" {
		t.Fatalf("new service account Status = %q, want active", sa.Status)
	}
	t.Cleanup(func() {
		_, _ = doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/service-accounts/"+sa.ID, adminToken, nil, nil)
	})

	// --- role + path policy: payment-reader -> prod/payment/* -> read ---
	roleID := createCustomRole(t, env, "payment-reader-"+suffix, "secrets:read")
	policyID := createPolicyAsAdmin(t, env, client, adminToken, "payment-read-"+suffix, []map[string]any{readRule("prod/payment/*", "read")})
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)

	assignRes, assignBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/service-accounts/"+sa.ID+"/roles", adminToken,
		map[string]any{"role_id": roleID}, nil)
	if assignRes.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/service-accounts/%s/roles: status = %d, want 201; body = %s", sa.ID, assignRes.StatusCode, assignBody)
	}

	// --- issue a credential ---
	keyRes, keyBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/api-keys", adminToken,
		map[string]any{"name": "ci-key", "owner_service_account_id": sa.ID}, nil)
	if keyRes.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/api-keys: status = %d, want 201; body = %s", keyRes.StatusCode, keyBody)
	}
	var created dto.ApiKeyCreatedResponse
	if err := json.Unmarshal(keyBody, &created); err != nil {
		t.Fatalf("decode ApiKeyCreatedResponse: %v", err)
	}
	if created.Secret == "" {
		t.Fatal("ApiKeyCreatedResponse.Secret is empty")
	}

	// --- seed two secrets, one inside and one outside the granted path ---
	createSecretRes, createSecretBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
		map[string]any{"path": "prod/payment/database", "data": map[string]string{"password": "s3cr3t"}}, nil)
	if createSecretRes.StatusCode != http.StatusCreated {
		t.Fatalf("seed prod/payment/database: status = %d; body = %s", createSecretRes.StatusCode, createSecretBody)
	}
	createSecretRes2, createSecretBody2 := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
		map[string]any{"path": "prod/hr/database", "data": map[string]string{"password": "s3cr3t"}}, nil)
	if createSecretRes2.StatusCode != http.StatusCreated {
		t.Fatalf("seed prod/hr/database: status = %d; body = %s", createSecretRes2.StatusCode, createSecretBody2)
	}

	// --- exchange the credential for an access token ---
	tokenRes, tokenBody := postWithAPIKey(t, client, env.Server.URL+"/v1/service-accounts/"+sa.ID+"/token", created.Secret, nil)
	if tokenRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/service-accounts/%s/token: status = %d, want 200; body = %s", sa.ID, tokenRes.StatusCode, tokenBody)
	}
	var tok dto.ServiceTokenResponse
	if err := json.Unmarshal(tokenBody, &tok); err != nil {
		t.Fatalf("decode ServiceTokenResponse: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("ServiceTokenResponse.AccessToken is empty")
	}

	// --- the payment-service example itself: ALLOW inside, DENY outside ---
	allowedRes, allowedBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/prod/payment/database", tok.AccessToken, nil, nil)
	if allowedRes.StatusCode != http.StatusOK {
		t.Errorf("GET prod/payment/database with the service account's token: status = %d, want 200; body = %s", allowedRes.StatusCode, allowedBody)
	}
	deniedRes, deniedBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/prod/hr/database", tok.AccessToken, nil, nil)
	if deniedRes.StatusCode != http.StatusForbidden {
		t.Errorf("GET prod/hr/database with the service account's token: status = %d, want 403 (outside its granted path); body = %s", deniedRes.StatusCode, deniedBody)
	}

	// --- revoked credential: 401, distinct from a disabled account ---
	revokeRes, revokeBody := doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/api-keys/"+created.ID, adminToken, nil, nil)
	if revokeRes.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /v1/api-keys/%s: status = %d, want 204; body = %s", created.ID, revokeRes.StatusCode, revokeBody)
	}
	revokedAuthRes, revokedAuthBody := postWithAPIKey(t, client, env.Server.URL+"/v1/service-accounts/"+sa.ID+"/token", created.Secret, nil)
	if revokedAuthRes.StatusCode != http.StatusUnauthorized {
		t.Errorf("token exchange with a revoked credential: status = %d, want 401; body = %s", revokedAuthRes.StatusCode, revokedAuthBody)
	}

	// --- disabled service account: 403, and a fresh credential still fails ---
	newKeyRes, newKeyBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/api-keys", adminToken,
		map[string]any{"name": "second-key", "owner_service_account_id": sa.ID}, nil)
	if newKeyRes.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/api-keys (second key): status = %d; body = %s", newKeyRes.StatusCode, newKeyBody)
	}
	var secondKey dto.ApiKeyCreatedResponse
	if err := json.Unmarshal(newKeyBody, &secondKey); err != nil {
		t.Fatalf("decode ApiKeyCreatedResponse (second key): %v", err)
	}

	disableRes, disableBody := doAuthed(t, client, http.MethodPatch, env.Server.URL+"/v1/service-accounts/"+sa.ID, adminToken,
		map[string]any{"name": sa.Name, "status": "disabled"}, nil)
	if disableRes.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /v1/service-accounts/%s (disable): status = %d, want 200; body = %s", sa.ID, disableRes.StatusCode, disableBody)
	}

	disabledAuthRes, disabledAuthBody := postWithAPIKey(t, client, env.Server.URL+"/v1/service-accounts/"+sa.ID+"/token", secondKey.Secret, nil)
	if disabledAuthRes.StatusCode != http.StatusForbidden {
		t.Errorf("token exchange against a disabled service account: status = %d, want 403; body = %s", disabledAuthRes.StatusCode, disabledAuthBody)
	}

	// --- audit trail: the whole flow left a real, generic-messaged trail ---
	auditRes, auditBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/audit-logs?limit=100", adminToken, nil, nil)
	if auditRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/audit-logs: status = %d; body = %s", auditRes.StatusCode, auditBody)
	}
	for _, leak := range []string{created.Secret, secondKey.Secret, tok.AccessToken} {
		if leak != "" && strings.Contains(string(auditBody), leak) {
			t.Errorf("audit log response unexpectedly contains a raw secret or token value")
		}
	}
}

// TestServiceAccountsE2E_OrdinaryUserCannotAdminister proves the
// objective's own "normal users must not create arbitrary machine
// identities" requirement: an authenticated user holding no
// service_accounts:* permission is rejected exactly like any other
// permission-gated admin route.
func TestServiceAccountsE2E_OrdinaryUserCannotAdminister(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, plainToken := registerPlainUser(t, env)

	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/service-accounts", plainToken,
		map[string]any{"name": "should-not-be-created"}, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("POST /v1/service-accounts as a plain user: status = %d, want 403; body = %s", res.StatusCode, body)
	}

	unauthRes, unauthBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/service-accounts", "", nil, nil)
	if unauthRes.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /v1/service-accounts unauthenticated: status = %d, want 401; body = %s", unauthRes.StatusCode, unauthBody)
	}
}
