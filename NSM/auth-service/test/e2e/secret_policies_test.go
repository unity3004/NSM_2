//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/dto"
)

// createCustomRole inserts a fresh, org-scoped role directly into the
// database and grants it the given "resource:action" permission strings —
// the same "there is no API for creating a role, so this is direct-to-
// database test setup" convention registerAndLoginWithRole's own doc
// comment already establishes for role *assignment* (test/e2e/user_role_management_test.go);
// this extends it one level up, to the role itself, since this suite needs
// roles that hold secrets:* without also holding the seeded system roles'
// backward-compatibility "Full Access" policy (see migrations/000027's own
// doc comment on why Platform Administrator/Security Engineer/Developer
// all already carry it, which would make "has secrets:read but no path
// policy" impossible to construct from the seeded roles alone).
func createCustomRole(t *testing.T, env *e2eEnv, name string, permissions ...string) string {
	t.Helper()
	var roleID string
	err := env.DB.QueryRowContext(context.Background(),
		`INSERT INTO roles (organization_id, name) VALUES ($1, $2) RETURNING id`, fixtureOrgID, name).Scan(&roleID)
	if err != nil {
		t.Fatalf("create custom role %q: %v", name, err)
	}
	t.Cleanup(func() {
		if _, err := env.DB.Exec(`DELETE FROM roles WHERE id = $1`, roleID); err != nil {
			t.Logf("cleanup: delete custom role %s: %v", roleID, err)
		}
	})
	for _, p := range permissions {
		resource, action, _ := strings.Cut(p, ":")
		res, err := env.DB.Exec(`
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT $1, id FROM permissions WHERE resource = $2 AND action = $3`, roleID, resource, action)
		if err != nil {
			t.Fatalf("grant %q to custom role %q: %v", p, name, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("grant %q to custom role %q: no matching permission row found", p, name)
		}
	}
	return roleID
}

// createPolicyAsAdmin creates a policy via the real admin API (POST
// /v1/secret-policies) and registers cleanup — the "use the real API for
// anything that has one" counterpart to createCustomRole's direct-to-
// database approach for the one thing (role creation) that has none.
func createPolicyAsAdmin(t *testing.T, env *e2eEnv, client *http.Client, adminToken, name string, rules []map[string]any) string {
	t.Helper()
	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secret-policies", adminToken,
		map[string]any{"name": name, "rules": rules}, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/secret-policies: status = %d, want 201; body = %s", res.StatusCode, body)
	}
	var p dto.SecretPolicyResponse
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode SecretPolicyResponse: %v", err)
	}
	t.Cleanup(func() {
		if _, err := env.DB.Exec(`DELETE FROM secret_policies WHERE id = $1`, p.ID); err != nil {
			t.Logf("cleanup: delete policy %s: %v", p.ID, err)
		}
	})
	return p.ID
}

func assignPolicyAsAdmin(t *testing.T, env *e2eEnv, client *http.Client, adminToken, policyID, roleID string) {
	t.Helper()
	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secret-policies/"+policyID+"/assignments", adminToken,
		map[string]any{"role_id": roleID}, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/secret-policies/%s/assignments: status = %d, want 204; body = %s", policyID, res.StatusCode, body)
	}
}

func readRule(pathPattern string, actions ...string) map[string]any {
	return map[string]any{"path_pattern": pathPattern, "actions": toAnySlice(actions)}
}

func denyRule(pathPattern string, actions ...string) map[string]any {
	return map[string]any{"path_pattern": pathPattern, "effect": "deny", "actions": toAnySlice(actions)}
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func createSecretAsAdmin(t *testing.T, env *e2eEnv, client *http.Client, adminToken, path string) {
	t.Helper()
	res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
		map[string]any{"path": path, "data": map[string]string{"k": "v"}}, nil)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/secrets (seed %q): status = %d, want 201; body = %s", path, res.StatusCode, body)
	}
}

// ===================================================================
// ADMIN API: authentication, authorization, and full CRUD lifecycle
// ===================================================================

func TestSecretPoliciesE2E_AdminAPI_Unauthenticated_Returns401(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()

	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/v1/secret-policies"},
		{http.MethodGet, "/v1/secret-policies"},
		{http.MethodGet, "/v1/secret-policies/does-not-matter"},
		{http.MethodPut, "/v1/secret-policies/does-not-matter"},
		{http.MethodDelete, "/v1/secret-policies/does-not-matter"},
		{http.MethodPost, "/v1/secret-policies/does-not-matter/assignments"},
		{http.MethodGet, "/v1/secret-policies/does-not-matter/assignments"},
		{http.MethodDelete, "/v1/secret-policies/does-not-matter/assignments/role-x"},
	} {
		t.Run(req.method+" "+req.path, func(t *testing.T) {
			res, body := doAuthed(t, client, req.method, env.Server.URL+req.path, "", nil, nil)
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401; body = %s", res.StatusCode, body)
			}
		})
	}
}

func TestSecretPoliciesE2E_AdminAPI_NonAdminForbidden(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	// A Developer holds secrets:read but not any secret_policies:*
	// permission (migrations/000028 grants those to Platform
	// Administrator only) — the objective's own "non-admin cannot manage
	// policies" requirement.
	token, _ := registerAndLoginWithRole(t, env, client, roleDeveloper)

	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/v1/secret-policies"},
		{http.MethodGet, "/v1/secret-policies"},
		{http.MethodGet, "/v1/secret-policies/does-not-matter"},
		{http.MethodPut, "/v1/secret-policies/does-not-matter"},
		{http.MethodDelete, "/v1/secret-policies/does-not-matter"},
		{http.MethodPost, "/v1/secret-policies/does-not-matter/assignments"},
		{http.MethodDelete, "/v1/secret-policies/does-not-matter/assignments/role-x"},
	} {
		t.Run(req.method+" "+req.path, func(t *testing.T) {
			res, body := doAuthed(t, client, req.method, env.Server.URL+req.path, token, map[string]any{"name": "x", "rules": []any{}}, nil)
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403; body = %s", res.StatusCode, body)
			}
		})
	}
}

func TestSecretPoliciesE2E_AdminAPI_FullCRUDLifecycle(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	// --- Create ---
	createRes, createBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secret-policies", adminToken,
		map[string]any{
			"name":        "e2e-lifecycle-" + suffix,
			"description": "created by the admin API lifecycle test",
			"rules":       []any{readRule("dev/*", "read", "create")},
		}, nil)
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/secret-policies: status = %d, want 201; body = %s", createRes.StatusCode, createBody)
	}
	var created dto.SecretPolicyResponse
	if err := json.Unmarshal(createBody, &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	t.Cleanup(func() { env.DB.Exec(`DELETE FROM secret_policies WHERE id = $1`, created.ID) })
	if created.Name != "e2e-lifecycle-"+suffix {
		t.Errorf("created.Name = %q, want %q", created.Name, "e2e-lifecycle-"+suffix)
	}

	// --- Get (detail, with rules) ---
	getRes, getBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secret-policies/"+created.ID, adminToken, nil, nil)
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/secret-policies/%s: status = %d, want 200; body = %s", created.ID, getRes.StatusCode, getBody)
	}
	var detail dto.SecretPolicyDetailResponse
	if err := json.Unmarshal(getBody, &detail); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if len(detail.Rules) != 1 || detail.Rules[0].PathPattern != "dev/*" {
		t.Errorf("detail.Rules = %+v, want one dev/* rule", detail.Rules)
	}

	// --- List ---
	listRes, listBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secret-policies", adminToken, nil, nil)
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/secret-policies: status = %d, want 200; body = %s", listRes.StatusCode, listBody)
	}
	var list struct {
		Data []dto.SecretPolicyResponse `json:"data"`
	}
	if err := json.Unmarshal(listBody, &list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	found := false
	for _, p := range list.Data {
		if p.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Error("list did not include the just-created policy")
	}

	// --- Update (rename, replace rules) ---
	updateRes, updateBody := doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secret-policies/"+created.ID, adminToken,
		map[string]any{"name": "e2e-lifecycle-renamed-" + suffix, "rules": []any{readRule("staging/*", "read")}}, nil)
	if updateRes.StatusCode != http.StatusOK {
		t.Fatalf("PUT /v1/secret-policies/%s: status = %d, want 200; body = %s", created.ID, updateRes.StatusCode, updateBody)
	}
	getRes2, getBody2 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secret-policies/"+created.ID, adminToken, nil, nil)
	if getRes2.StatusCode != http.StatusOK {
		t.Fatalf("GET after update: status = %d; body = %s", getRes2.StatusCode, getBody2)
	}
	var updatedDetail dto.SecretPolicyDetailResponse
	_ = json.Unmarshal(getBody2, &updatedDetail)
	if updatedDetail.Name != "e2e-lifecycle-renamed-"+suffix {
		t.Errorf("Name after update = %q, want the renamed value", updatedDetail.Name)
	}
	if len(updatedDetail.Rules) != 1 || updatedDetail.Rules[0].PathPattern != "staging/*" {
		t.Errorf("Rules after update = %+v, want exactly one staging/* rule (old dev/* rule must be gone)", updatedDetail.Rules)
	}

	// --- Assign / list assignments / unassign ---
	customRole := createCustomRole(t, env, "e2e-lifecycle-role-"+suffix, "secrets:read")
	assignRes, assignBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secret-policies/"+created.ID+"/assignments", adminToken,
		map[string]any{"role_id": customRole}, nil)
	if assignRes.StatusCode != http.StatusNoContent {
		t.Fatalf("POST assignments: status = %d, want 204; body = %s", assignRes.StatusCode, assignBody)
	}
	assignmentsRes, assignmentsBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secret-policies/"+created.ID+"/assignments", adminToken, nil, nil)
	if assignmentsRes.StatusCode != http.StatusOK {
		t.Fatalf("GET assignments: status = %d, want 200; body = %s", assignmentsRes.StatusCode, assignmentsBody)
	}
	var assignments struct {
		Data []string `json:"data"`
	}
	_ = json.Unmarshal(assignmentsBody, &assignments)
	if len(assignments.Data) != 1 || assignments.Data[0] != customRole {
		t.Errorf("assignments = %v, want [%q]", assignments.Data, customRole)
	}
	unassignRes, unassignBody := doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/secret-policies/"+created.ID+"/assignments/"+customRole, adminToken, nil, nil)
	if unassignRes.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE assignment: status = %d, want 204; body = %s", unassignRes.StatusCode, unassignBody)
	}

	// --- Delete, then verify it's gone ---
	deleteRes, deleteBody := doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/secret-policies/"+created.ID, adminToken, nil, nil)
	if deleteRes.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /v1/secret-policies/%s: status = %d, want 204; body = %s", created.ID, deleteRes.StatusCode, deleteBody)
	}
	getRes3, getBody3 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secret-policies/"+created.ID, adminToken, nil, nil)
	if getRes3.StatusCode != http.StatusNotFound {
		t.Errorf("GET after delete: status = %d, want 404; body = %s", getRes3.StatusCode, getBody3)
	}

	// --- Audit: every admin action left a trail ---
	for _, action := range []string{"policy.created", "policy.updated", "policy.assigned", "policy.unassigned", "policy.deleted"} {
		if n := auditCount(t, env, action, created.ID); n < 1 {
			t.Errorf("audit_logs has %d rows for action=%q resource_id=%q, want at least 1", n, action, created.ID)
		}
	}
}

func TestSecretPoliciesE2E_AdminAPI_ValidationErrors(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	tests := []struct {
		name string
		body map[string]any
	}{
		{"empty name", map[string]any{"name": "", "rules": []any{readRule("dev/*", "read")}}},
		{"no rules", map[string]any{"name": "x-" + uniqueSuffix(t), "rules": []any{}}},
		{"traversal path pattern", map[string]any{"name": "x-" + uniqueSuffix(t), "rules": []any{readRule("prod/../etc", "read")}}},
		{"embedded wildcard", map[string]any{"name": "x-" + uniqueSuffix(t), "rules": []any{readRule("prod/*/database", "read")}}},
		{"unknown action", map[string]any{"name": "x-" + uniqueSuffix(t), "rules": []any{readRule("dev/*", "execute")}}},
		{"bad effect", map[string]any{"name": "x-" + uniqueSuffix(t), "rules": []any{map[string]any{"path_pattern": "dev/*", "effect": "maybe", "actions": []any{"read"}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secret-policies", adminToken, tt.body, nil)
			if res.StatusCode != http.StatusUnprocessableEntity {
				t.Errorf("status = %d, want 422; body = %s", res.StatusCode, body)
			}
		})
	}
}

// ===================================================================
// AUTHORIZATION FLOW: deny by default, path matching, layered RBAC
// ===================================================================

func TestSecretPoliciesE2E_DenyByDefault_ReadPermissionAloneIsNotEnough(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "restricted/" + suffix + "/db"
	createSecretAsAdmin(t, env, client, adminToken, path)

	// A role holding secrets:read but assigned no secret policy at all —
	// only reachable via a fresh custom role, since every seeded system
	// role that holds secrets:read was backfilled with the wildcard "Full
	// Access" policy by migrations/000027 (see createCustomRole's own doc
	// comment).
	roleID := createCustomRole(t, env, "e2e-read-no-policy-"+suffix, "secrets:read")
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("GET %s with secrets:read but no policy: status = %d, want 403; body = %s", path, res.StatusCode, body)
	}
}

func TestSecretPoliciesE2E_PolicyGrantsPathScopedAccess(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	devPath := "dev/" + suffix + "/db"
	prodPath := "prod/" + suffix + "/db"
	createSecretAsAdmin(t, env, client, adminToken, devPath)
	createSecretAsAdmin(t, env, client, adminToken, prodPath)

	policyID := createPolicyAsAdmin(t, env, client, adminToken, "e2e-dev-read-"+suffix, []map[string]any{
		readRule("dev/"+suffix+"/*", "read"),
	})
	roleID := createCustomRole(t, env, "e2e-dev-reader-"+suffix, "secrets:read")
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	t.Run("AuthorizedPath", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+devPath, token, nil, nil)
		if res.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200; body = %s", devPath, res.StatusCode, body)
		}
	})
	t.Run("UnauthorizedSiblingPath", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+prodPath, token, nil, nil)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s: status = %d, want 403; body = %s", prodPath, res.StatusCode, body)
		}
	})
}

func TestSecretPoliciesE2E_CreateRespectsPath(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	policyID := createPolicyAsAdmin(t, env, client, adminToken, "e2e-dev-create-"+suffix, []map[string]any{
		readRule("dev/"+suffix+"/*", "create"),
	})
	roleID := createCustomRole(t, env, "e2e-dev-creator-"+suffix, "secrets:create")
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	t.Run("AuthorizedPath", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", token,
			map[string]any{"path": "dev/" + suffix + "/new", "data": map[string]string{"k": "v"}}, nil)
		if res.StatusCode != http.StatusCreated {
			t.Errorf("POST dev/%s/new: status = %d, want 201; body = %s", suffix, res.StatusCode, body)
		}
	})
	t.Run("UnauthorizedPath", func(t *testing.T) {
		res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", token,
			map[string]any{"path": "prod/" + suffix + "/new", "data": map[string]string{"k": "v"}}, nil)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("POST prod/%s/new: status = %d, want 403; body = %s", suffix, res.StatusCode, body)
		}
	})
}

func TestSecretPoliciesE2E_ExplicitDenyPrecedence(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	dbPath := "prod/" + suffix + "/db"
	secretPath := "prod/" + suffix + "/secrets/token"
	createSecretAsAdmin(t, env, client, adminToken, dbPath)
	createSecretAsAdmin(t, env, client, adminToken, secretPath)

	policyID := createPolicyAsAdmin(t, env, client, adminToken, "e2e-deny-precedence-"+suffix, []map[string]any{
		readRule("prod/"+suffix+"/*", "read"),
		denyRule("prod/"+suffix+"/secrets/*", "read"),
	})
	roleID := createCustomRole(t, env, "e2e-deny-precedence-role-"+suffix, "secrets:read")
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+dbPath, token, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200 (broad allow applies); body = %s", dbPath, res.StatusCode, body)
	}
	res2, body2 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+secretPath, token, nil, nil)
	if res2.StatusCode != http.StatusForbidden {
		t.Errorf("GET %s: status = %d, want 403 (explicit deny must win over the broader allow); body = %s", secretPath, res2.StatusCode, body2)
	}
}

func TestSecretPoliciesE2E_PolicyChangesAffectAuthorization(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "dev/" + suffix + "/db"
	createSecretAsAdmin(t, env, client, adminToken, path)

	policyID := createPolicyAsAdmin(t, env, client, adminToken, "e2e-mutable-"+suffix, []map[string]any{
		readRule("dev/"+suffix+"/*", "read"),
	})
	roleID := createCustomRole(t, env, "e2e-mutable-role-"+suffix, "secrets:read")
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s before policy update: status = %d, want 200; body = %s", path, res.StatusCode, body)
	}

	// Narrow the policy's rules to a path that no longer covers `path`.
	updateRes, updateBody := doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secret-policies/"+policyID, adminToken,
		map[string]any{"name": "e2e-mutable-" + suffix, "rules": []any{readRule("staging/"+suffix+"/*", "read")}}, nil)
	if updateRes.StatusCode != http.StatusOK {
		t.Fatalf("PUT /v1/secret-policies/%s: status = %d, want 200; body = %s", policyID, updateRes.StatusCode, updateBody)
	}

	res2, body2 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
	if res2.StatusCode != http.StatusForbidden {
		t.Errorf("GET %s after the policy no longer covers it: status = %d, want 403; body = %s", path, res2.StatusCode, body2)
	}
}

func TestSecretPoliciesE2E_DeletedPolicyRevokesAccess(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "dev/" + suffix + "/db"
	createSecretAsAdmin(t, env, client, adminToken, path)

	policyID := createPolicyAsAdmin(t, env, client, adminToken, "e2e-deletable-"+suffix, []map[string]any{
		readRule("dev/"+suffix+"/*", "read"),
	})
	roleID := createCustomRole(t, env, "e2e-deletable-role-"+suffix, "secrets:read")
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	res, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s before delete: status = %d, want 200", path, res.StatusCode)
	}

	deleteRes, deleteBody := doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/secret-policies/"+policyID, adminToken, nil, nil)
	if deleteRes.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /v1/secret-policies/%s: status = %d, want 204; body = %s", policyID, deleteRes.StatusCode, deleteBody)
	}

	res2, body2 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
	if res2.StatusCode != http.StatusForbidden {
		t.Errorf("GET %s after DeletePolicy: status = %d, want 403 — a deleted policy must no longer grant access; body = %s", path, res2.StatusCode, body2)
	}
}

// ===================================================================
// LIST AUTHORIZATION: the objective's own worked example, reproduced
// against real HTTP — dev/database + dev/api visible, prod/* filtered out.
// ===================================================================

func TestSecretPoliciesE2E_ListFiltersUnauthorizedPaths(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	devDatabase := "dev/" + suffix + "/database"
	devAPI := "dev/" + suffix + "/api"
	prodDatabase := "prod/" + suffix + "/database"
	prodPayment := "prod/" + suffix + "/payment"
	for _, p := range []string{devDatabase, devAPI, prodDatabase, prodPayment} {
		createSecretAsAdmin(t, env, client, adminToken, p)
	}

	policyID := createPolicyAsAdmin(t, env, client, adminToken, "e2e-list-filter-"+suffix, []map[string]any{
		readRule("dev/"+suffix+"/*", "list"),
	})
	roleID := createCustomRole(t, env, "e2e-list-filter-role-"+suffix, "secrets:list")
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets", token, nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/secrets: status = %d, want 200; body = %s", res.StatusCode, body)
	}
	var out struct {
		Data []dto.SecretResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	seen := map[string]bool{}
	for _, s := range out.Data {
		seen[s.Path] = true
	}
	if !seen[devDatabase] || !seen[devAPI] {
		t.Errorf("list is missing an authorized path: seen = %v, want %q and %q present", seen, devDatabase, devAPI)
	}
	if seen[prodDatabase] || seen[prodPayment] {
		t.Errorf("list unexpectedly revealed an unauthorized path: seen = %v — must never include metadata for a path the caller has no policy for", seen)
	}
}

// ===================================================================
// SECURITY: bypass attempts against a dev-only-scoped actor
// ===================================================================

func TestSecretPoliciesE2E_BypassAttempts_AllDenied(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	devPath := "dev/" + suffix + "/db"
	prodPath := "prod/" + suffix + "/db"
	createSecretAsAdmin(t, env, client, adminToken, devPath)
	createSecretAsAdmin(t, env, client, adminToken, prodPath)

	policyID := createPolicyAsAdmin(t, env, client, adminToken, "e2e-bypass-"+suffix, []map[string]any{
		readRule("dev/"+suffix+"/*", "read"),
	})
	roleID := createCustomRole(t, env, "e2e-bypass-role-"+suffix, "secrets:read")
	assignPolicyAsAdmin(t, env, client, adminToken, policyID, roleID)
	token, _ := registerAndLoginWithRole(t, env, client, roleID)

	// Sanity: the baseline denial this whole test tries to route around.
	baseline, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+prodPath, token, nil, nil)
	if baseline.StatusCode != http.StatusForbidden {
		t.Fatalf("baseline GET %s: status = %d, want 403 — test setup is broken", prodPath, baseline.StatusCode)
	}

	attempts := []struct {
		name string
		path string
	}{
		{"dot-dot traversal", "/v1/secrets/dev/" + suffix + "/../../" + prodPath},
		{"encoded dot-dot traversal", "/v1/secrets/dev%2F" + suffix + "%2F..%2F..%2F" + prodPath},
		{"double leading slash collapses but stays denied", "/v1/secrets//" + prodPath},
		{"trailing slash collapses but stays denied", "/v1/secrets/" + prodPath + "/"},
		{"case variation on the authorized prefix", "/v1/secrets/DEV/" + suffix + "/db"},
		{"similar prefix without a path boundary", "/v1/secrets/dev" + suffix + "x/db"},
		{"duplicate internal slash", "/v1/secrets/dev/" + suffix + "//db"},
	}
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			res, body := doAuthed(t, client, http.MethodGet, env.Server.URL+a.path, token, nil, nil)
			if res.StatusCode == http.StatusOK {
				t.Errorf("GET %s unexpectedly returned 200 — bypass succeeded; body = %s", a.path, body)
			}
			lower := strings.ToLower(string(body))
			if strings.Contains(lower, `"v"`) { // the seeded secret value
				t.Errorf("GET %s response unexpectedly contains secret data: %s", a.path, body)
			}
		})
	}
}

// A 403 for a path that genuinely exists must be indistinguishable from a
// 403 for a path that doesn't — never a 404-vs-403 split that would leak
// existence to a caller with no policy covering that path.
func TestSecretPoliciesE2E_UnauthorizedRead_DoesNotRevealExistence(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	existingProdPath := "prod/" + suffix + "/db"
	createSecretAsAdmin(t, env, client, adminToken, existingProdPath)
	missingProdPath := "prod/" + suffix + "/does-not-exist"

	roleID := createCustomRole(t, env, "e2e-existence-role-"+suffix, "secrets:read")
	token, _ := registerAndLoginWithRole(t, env, client, roleID) // no policy at all — deny by default

	res1, body1 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+existingProdPath, token, nil, nil)
	res2, body2 := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+missingProdPath, token, nil, nil)

	if res1.StatusCode != http.StatusForbidden {
		t.Errorf("GET existing-but-unauthorized path: status = %d, want 403", res1.StatusCode)
	}
	if res2.StatusCode != http.StatusForbidden {
		t.Errorf("GET nonexistent-and-unauthorized path: status = %d, want 403 (not 404 — must not leak existence)", res2.StatusCode)
	}

	var err1, err2 dto.Error
	_ = json.Unmarshal(body1, &err1)
	_ = json.Unmarshal(body2, &err2)
	if err1.Error.Code != err2.Error.Code || err1.Error.Message != err2.Error.Message {
		t.Errorf("responses differ between an existing and a nonexistent path: %+v vs %+v — this would leak existence", err1, err2)
	}
}

// ===================================================================
// AUDIT: denied secret access is recorded, without leaking plaintext.
// ===================================================================

func TestSecretPoliciesE2E_DeniedAccess_IsAuditedWithoutLeakingSecretValues(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "prod/" + suffix + "/db"
	createSecretAsAdmin(t, env, client, adminToken, path)

	roleID := createCustomRole(t, env, "e2e-audit-denied-role-"+suffix, "secrets:read")
	token, userID := registerAndLoginWithRole(t, env, client, roleID)

	res, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, token, nil, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("GET %s: status = %d, want 403", path, res.StatusCode)
	}

	rows, err := env.DB.Query(`SELECT actor_id, result, resource_id, metadata::text FROM audit_logs WHERE action = 'secret.access_denied' AND actor_id = $1`, userID)
	if err != nil {
		t.Fatalf("query audit_logs: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var actorID, result, resourceID, metadata string
		if err := rows.Scan(&actorID, &result, &resourceID, &metadata); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		found = true
		if result != "denied" {
			t.Errorf("audit result = %q, want %q", result, "denied")
		}
		if resourceID != path {
			t.Errorf("audit resource_id = %q, want %q", resourceID, path)
		}
		lower := strings.ToLower(metadata)
		for _, forbidden := range []string{"ciphertext", "key_id", "nonce", "wrapped_dek", "\"v\""} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("audit metadata unexpectedly contains %q: %s", forbidden, metadata)
			}
		}
	}
	if !found {
		t.Error("no secret.access_denied audit row was recorded for this denied request")
	}
}
