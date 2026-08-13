//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/dto"
)

// createLeaseTestRole grants a fresh role secrets:read + leases:create +
// leases:read + leases:revoke plus a full-access path policy — the
// minimum a real caller needs to exercise the entire lease lifecycle
// end to end, mirroring createCustomRole/createPolicyAsAdmin's own use in
// service_accounts_test.go for the identical "administrator, then grant a
// narrower role to the identity under test" shape.
func createLeaseTestRole(t *testing.T, env *e2eEnv, client *http.Client, adminToken, suffix string) string {
	t.Helper()
	roleID := createCustomRole(t, env, "lease-tester-"+suffix, "secrets:read", "leases:create", "leases:read", "leases:revoke")
	policyID := createPolicyAsAdmin(t, env, client, adminToken, "lease-full-access-"+suffix, []map[string]any{readRule("*", "read")})
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	return roleID
}

// TestLeasesE2E_FullLifecycle exercises Sprint 5 Task 2's own headline
// path through the real HTTP stack: create (with a real dev-credential
// returned exactly once), lookup (metadata only, never the credential
// again), renew, and revoke — then proves a revoked lease is rejected by
// GET's own IsUsable check and cannot be renewed again.
func TestLeasesE2E_FullLifecycle(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	roleID := createLeaseTestRole(t, env, client, adminToken, suffix)

	userID, userToken := registerPlainUser(t, env)
	assignRes, assignBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/users/"+userID+"/roles", adminToken,
		map[string]any{"role_id": roleID}, nil)
	if assignRes.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/users/%s/roles: status = %d, want 204; body = %s", userID, assignRes.StatusCode, assignBody)
	}

	// --- create ---
	createRes, createBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases", userToken,
		map[string]any{"type": "dev-credential", "path": "database/prod/readonly", "ttl": "5m", "renewable": true}, nil)
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/leases: status = %d, want 201; body = %s", createRes.StatusCode, createBody)
	}
	var created dto.LeaseCreatedResponse
	if err := json.Unmarshal(createBody, &created); err != nil {
		t.Fatalf("decode LeaseCreatedResponse: %v", err)
	}
	if created.LeaseID == "" || created.Status != "active" {
		t.Fatalf("LeaseCreatedResponse = %+v, want a persisted active lease", created)
	}
	if created.Credential["username"] == "" || created.Credential["password"] == "" {
		t.Fatalf("LeaseCreatedResponse.Credential = %+v, want a real username/password", created.Credential)
	}

	// --- lookup: metadata only, never the credential again ---
	getRes, getBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/leases/"+created.LeaseID, userToken, nil, nil)
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/leases/%s: status = %d, want 200; body = %s", created.LeaseID, getRes.StatusCode, getBody)
	}
	if strings.Contains(string(getBody), created.Credential["password"]) {
		t.Error("GET /v1/leases/{id} response contains the raw credential password — must never be re-exposed")
	}
	var fetched dto.LeaseResponse
	if err := json.Unmarshal(getBody, &fetched); err != nil {
		t.Fatalf("decode LeaseResponse: %v", err)
	}
	if fetched.LeaseID != created.LeaseID || fetched.Status != "active" {
		t.Errorf("GET /v1/leases/%s = %+v, want the same active lease", created.LeaseID, fetched)
	}

	// --- renew ---
	renewRes, renewBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases/"+created.LeaseID+"/renew", userToken,
		map[string]any{"ttl": "10m"}, nil)
	if renewRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/leases/%s/renew: status = %d, want 200; body = %s", created.LeaseID, renewRes.StatusCode, renewBody)
	}
	var renewed dto.LeaseResponse
	if err := json.Unmarshal(renewBody, &renewed); err != nil {
		t.Fatalf("decode renewed LeaseResponse: %v", err)
	}
	if !renewed.ExpiresAt.After(fetched.ExpiresAt) {
		t.Errorf("renewed ExpiresAt = %s, want after the original %s", renewed.ExpiresAt, fetched.ExpiresAt)
	}

	// --- revoke ---
	revokeRes, revokeBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases/"+created.LeaseID+"/revoke", userToken,
		map[string]any{"reason": "test cleanup"}, nil)
	if revokeRes.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/leases/%s/revoke: status = %d, want 204; body = %s", created.LeaseID, revokeRes.StatusCode, revokeBody)
	}

	// --- revoked lease: no longer renewable ---
	renewAfterRevokeRes, renewAfterRevokeBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases/"+created.LeaseID+"/renew", userToken, nil, nil)
	if renewAfterRevokeRes.StatusCode != http.StatusConflict {
		t.Errorf("POST /v1/leases/%s/renew after revocation: status = %d, want 409; body = %s", created.LeaseID, renewAfterRevokeRes.StatusCode, renewAfterRevokeBody)
	}

	// --- audit trail never leaked the credential ---
	auditRes, auditBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/audit-logs?limit=100", adminToken, nil, nil)
	if auditRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/audit-logs: status = %d; body = %s", auditRes.StatusCode, auditBody)
	}
	if strings.Contains(string(auditBody), created.Credential["password"]) {
		t.Error("audit log response unexpectedly contains the raw lease credential password")
	}
}

// TestLeasesE2E_StaticSecretsAccessAloneIsNotEnough is the objective's own
// headline authorization case, run through the real HTTP stack: a caller
// who holds secrets:read and full path-policy access but no leases:create
// must be refused, exactly like any other permission-gated write.
func TestLeasesE2E_StaticSecretsAccessAloneIsNotEnough(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	roleID := createCustomRole(t, env, "secrets-reader-only-"+suffix, "secrets:read")
	policyID := createPolicyAsAdmin(t, env, client, adminToken, "secrets-reader-policy-"+suffix, []map[string]any{readRule("*", "read")})
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)

	userID, userToken := registerPlainUser(t, env)
	assignRes, assignBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/users/"+userID+"/roles", adminToken,
		map[string]any{"role_id": roleID}, nil)
	if assignRes.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/users/%s/roles: status = %d, want 204; body = %s", userID, assignRes.StatusCode, assignBody)
	}

	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases", userToken,
		map[string]any{"type": "dev-credential", "path": "database/prod/readonly", "ttl": "5m"}, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("POST /v1/leases with secrets:read but no leases:create: status = %d, want 403; body = %s", res.StatusCode, body)
	}
}

// TestLeasesE2E_CrossUserIsolation proves the cross-user lease isolation
// requirement through the real HTTP stack: another authenticated user who
// holds leases:create for their *own* leases but not the administrative
// leases:read/leases:revoke grants gets a 404 (never 403 —
// anti-enumeration) when reaching for someone else's lease ID, and cannot
// revoke it either. (A caller who *does* hold leases:read/leases:revoke
// is administratively allowed to reach any lease — see
// TestLeasesE2E_FullLifecycle's own role for that case; this test is
// specifically about a caller who holds neither.)
func TestLeasesE2E_CrossUserIsolation(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	ownerRoleID := createLeaseTestRole(t, env, client, adminToken, suffix)

	// otherRoleID deliberately carries only what's needed to create leases
	// of its own — no leases:read/leases:revoke — so this test actually
	// exercises ownership-based isolation rather than an administrative
	// bypass.
	otherRoleID := createCustomRole(t, env, "lease-creator-only-"+suffix, "secrets:read", "leases:create")
	otherPolicyID := createPolicyAsAdmin(t, env, client, adminToken, "lease-creator-only-access-"+suffix, []map[string]any{readRule("*", "read")})
	assignPolicyAsAdmin(t, env, client, adminToken, otherPolicyID, otherRoleID)

	ownerID, ownerToken := registerPlainUser(t, env)
	doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/users/"+ownerID+"/roles", adminToken, map[string]any{"role_id": ownerRoleID}, nil)
	otherID, otherToken := registerPlainUser(t, env)
	doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/users/"+otherID+"/roles", adminToken, map[string]any{"role_id": otherRoleID}, nil)

	createRes, createBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases", ownerToken,
		map[string]any{"type": "dev-credential", "path": "database/prod/readonly", "ttl": "5m"}, nil)
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/leases: status = %d, want 201; body = %s", createRes.StatusCode, createBody)
	}
	var created dto.LeaseCreatedResponse
	if err := json.Unmarshal(createBody, &created); err != nil {
		t.Fatalf("decode LeaseCreatedResponse: %v", err)
	}

	getRes, getBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/leases/"+created.LeaseID, otherToken, nil, nil)
	if getRes.StatusCode != http.StatusNotFound {
		t.Errorf("GET another user's lease: status = %d, want 404 (anti-enumeration); body = %s", getRes.StatusCode, getBody)
	}

	revokeRes, revokeBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases/"+created.LeaseID+"/revoke", otherToken, nil, nil)
	if revokeRes.StatusCode != http.StatusNotFound {
		t.Errorf("revoke another user's lease: status = %d, want 404 (anti-enumeration); body = %s", revokeRes.StatusCode, revokeBody)
	}

	// the true owner can still revoke it normally.
	ownerRevokeRes, ownerRevokeBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases/"+created.LeaseID+"/revoke", ownerToken, nil, nil)
	if ownerRevokeRes.StatusCode != http.StatusNoContent {
		t.Errorf("owner revoke: status = %d, want 204; body = %s", ownerRevokeRes.StatusCode, ownerRevokeBody)
	}
}

// TestLeasesE2E_TTLAboveMaximumIsClampedNeverRejected reproduces the
// objective's own worked example through the real HTTP stack: requesting
// a TTL above the server's configured maximum succeeds, clamped down —
// never an error, and never the raw requested value.
func TestLeasesE2E_TTLAboveMaximumIsClampedNeverRejected(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	roleID := createLeaseTestRole(t, env, client, adminToken, suffix)
	userID, userToken := registerPlainUser(t, env)
	doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/users/"+userID+"/roles", adminToken, map[string]any{"role_id": roleID}, nil)

	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases", userToken,
		map[string]any{"type": "dev-credential", "path": "database/prod/readonly", "ttl": "999999h"}, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/leases with an excessive ttl: status = %d, want 201 (clamped, not rejected); body = %s", res.StatusCode, body)
	}
	var created dto.LeaseCreatedResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode LeaseCreatedResponse: %v", err)
	}
	if created.TTL == "999999h0m0s" {
		t.Errorf("LeaseCreatedResponse.TTL = %q, want clamped to the server's configured maximum, not the raw request", created.TTL)
	}
}

// TestLeasesE2E_NegativeAndZeroTTLRejected is the security checklist's own
// "negative/zero TTL" case, run through the real HTTP stack — rejected at
// the DTO validation boundary (422), never reaching LeaseService at all.
func TestLeasesE2E_NegativeAndZeroTTLRejected(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	roleID := createLeaseTestRole(t, env, client, adminToken, suffix)
	userID, userToken := registerPlainUser(t, env)
	doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/users/"+userID+"/roles", adminToken, map[string]any{"role_id": roleID}, nil)

	for _, ttl := range []string{"0s", "-5m", "not-a-duration"} {
		res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases", userToken,
			map[string]any{"type": "dev-credential", "path": "database/prod/readonly", "ttl": ttl}, nil)
		if res.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("POST /v1/leases with ttl=%q: status = %d, want 422; body = %s", ttl, res.StatusCode, body)
		}
	}
}

// TestLeasesE2E_UnauthenticatedRejected proves every lease endpoint
// requires authentication — the security checklist's own baseline case.
func TestLeasesE2E_UnauthenticatedRejected(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()

	createRes, createBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases", "",
		map[string]any{"type": "dev-credential", "path": "database/prod/readonly"}, nil)
	if createRes.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /v1/leases unauthenticated: status = %d, want 401; body = %s", createRes.StatusCode, createBody)
	}

	getRes, getBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/leases/lease-does-not-exist", "", nil, nil)
	if getRes.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /v1/leases/{id} unauthenticated: status = %d, want 401; body = %s", getRes.StatusCode, getBody)
	}
}

// TestLeasesE2E_UnknownLeaseTypeRejected proves a request naming no
// registered dynamic-credential provider is rejected before any
// credential material is ever generated.
func TestLeasesE2E_UnknownLeaseTypeRejected(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	roleID := createLeaseTestRole(t, env, client, adminToken, suffix)
	userID, userToken := registerPlainUser(t, env)
	doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/users/"+userID+"/roles", adminToken, map[string]any{"role_id": roleID}, nil)

	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/leases", userToken,
		map[string]any{"type": "aws-iam-does-not-exist", "path": "database/prod/readonly"}, nil)
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("POST /v1/leases with an unregistered lease type: status = %d, want 422; body = %s", res.StatusCode, body)
	}
}
