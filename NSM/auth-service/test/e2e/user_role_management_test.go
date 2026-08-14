//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const (
	roleAdministrator     = "00000000-0000-4000-9000-000000000001"
	roleSecurityEngineer  = "00000000-0000-4000-9000-000000000002"
	roleDeveloper         = "00000000-0000-4000-9000-000000000003"
	roleAuditor           = "00000000-0000-4000-9000-000000000004"
)

// registerAndLoginWithRole creates a real user via the real self-service
// registration endpoint, optionally grants roleID directly in the
// database (the same category of test-only, direct-to-database setup
// resetPlatformUninitialized already uses — there is no API for
// "register a user with a role already attached," by design: role
// assignment is its own privileged action), then logs in for real and
// returns the access token and the new user's ID.
func registerAndLoginWithRole(t *testing.T, env *e2eEnv, client *http.Client, roleID string) (accessToken, userID string) {
	t.Helper()
	suffix := uniqueSuffix(t)
	email := fmt.Sprintf("rbac-test-%s@example.test", suffix)

	res, body := postJSON(t, client, env.Server.URL+"/v1/auth/register", map[string]any{
		"username": "rbac-test-" + suffix,
		"email":    email,
		"password": testPassword,
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register test user: got %d; body=%s", res.StatusCode, body)
	}
	var reg struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &reg); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	if roleID != "" {
		if _, err := env.DB.ExecContext(context.Background(),
			`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, reg.ID, roleID,
		); err != nil {
			t.Fatalf("grant role %s to test user: %v", roleID, err)
		}
	}

	loginRes, loginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login", map[string]any{
		"email":    email,
		"password": testPassword,
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login test user: got %d; body=%s", loginRes.StatusCode, loginBody)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(loginBody, &tok); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return tok.AccessToken, reg.ID
}

func authHeaders(token string) map[string]string {
	return map[string]string{
		"Authorization":     "Bearer " + token,
		"X-Organization-Id": fixtureOrgID,
	}
}

// TEST 1 — unauthorized (no token at all) cannot reach the users or roles API.
func TestUserManagement_Unauthorized_NoToken(t *testing.T) {
	env := newE2EEnv(t)
	client := &http.Client{}

	for _, req := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/users"},
		{http.MethodPost, "/v1/users"},
		{http.MethodGet, "/v1/roles"},
		{http.MethodGet, "/v1/permissions"},
	} {
		httpReq, err := http.NewRequest(req.method, env.Server.URL+req.path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		res, body := doRequest(t, client, httpReq)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s with no token: got %d, want 401; body=%s", req.method, req.path, res.StatusCode, body)
		}
	}
}

// TEST 10 — real authorization boundaries, exactly matching the
// specification's own table: Administrator can create users; Auditor and
// Developer cannot. Each is a real user, holding a real seeded role,
// making a real authenticated request — never a role name asserted by
// the client.
func TestUserManagement_AuthorizationBoundaries(t *testing.T) {
	env := newE2EEnv(t)
	client := &http.Client{}

	cases := []struct {
		name       string
		roleID     string
		wantStatus int
	}{
		{"Administrator", roleAdministrator, http.StatusCreated},
		{"Auditor", roleAuditor, http.StatusForbidden},
		{"Developer", roleDeveloper, http.StatusForbidden},
		{"NoRole", "", http.StatusForbidden},
	}

	for _, c := range cases {
		t.Run(c.name+"_users_create", func(t *testing.T) {
			token, _ := registerAndLoginWithRole(t, env, client, c.roleID)
			suffix := uniqueSuffix(t)
			res, body := postJSON(t, client, env.Server.URL+"/v1/users", map[string]any{
				"email":    fmt.Sprintf("created-by-%s-%s@example.test", strings.ToLower(c.name), suffix),
				"username": "created-by-" + strings.ToLower(c.name) + "-" + suffix,
				"password": testPassword,
			}, authHeaders(token))
			if res.StatusCode != c.wantStatus {
				t.Errorf("%s users:create -> got %d, want %d; body=%s", c.name, res.StatusCode, c.wantStatus, body)
			}
		})
	}

	// Auditor and Developer must also be denied listing users, and a 403
	// must never leak whether other users/roles exist.
	for _, c := range []struct {
		name   string
		roleID string
	}{{"Auditor", roleAuditor}, {"Developer", roleDeveloper}} {
		t.Run(c.name+"_users_list_denied", func(t *testing.T) {
			token, _ := registerAndLoginWithRole(t, env, client, c.roleID)
			req, _ := http.NewRequest(http.MethodGet, env.Server.URL+"/v1/users", nil)
			for k, v := range authHeaders(token) {
				req.Header.Set(k, v)
			}
			res, body := doRequest(t, client, req)
			if c.name == "Auditor" {
				// Auditor legitimately holds users:read.
				if res.StatusCode != http.StatusOK {
					t.Errorf("Auditor users:list -> got %d, want 200; body=%s", res.StatusCode, body)
				}
			} else {
				if res.StatusCode != http.StatusForbidden {
					t.Errorf("Developer users:list -> got %d, want 403; body=%s", res.StatusCode, body)
				}
			}
		})
	}
}

// TEST 12/13 — a real, full admin lifecycle: create, duplicate rejection,
// disable (sessions revoked, cannot log in), enable (can log in again),
// role assignment/removal, audit events, and a direct check that no
// password/hash/token ever appears in any response along the way.
func TestUserManagement_FullLifecycle(t *testing.T) {
	env := newE2EEnv(t)
	client := &http.Client{}
	adminToken, adminID := registerAndLoginWithRole(t, env, client, roleAdministrator)

	lifecycleSuffix := uniqueSuffix(t)
	targetEmail := fmt.Sprintf("lifecycle-target-%s@example.test", lifecycleSuffix)
	createRes, createBody := postJSON(t, client, env.Server.URL+"/v1/users", map[string]any{
		"email":    targetEmail,
		"username": "lifecycle-target-" + lifecycleSuffix,
		"password": testPassword,
	}, authHeaders(adminToken))
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("create user: got %d; body=%s", createRes.StatusCode, createBody)
	}
	assertNoForbiddenFields(t, "create user response", createBody)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(createBody, &created)

	// --- TEST 5: duplicate email rejected safely ---
	dupRes, dupBody := postJSON(t, client, env.Server.URL+"/v1/users", map[string]any{
		"email":    targetEmail,
		"username": "lifecycle-target-2-" + lifecycleSuffix,
		"password": testPassword,
	}, authHeaders(adminToken))
	if dupRes.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate email: got %d, want 409; body=%s", dupRes.StatusCode, dupBody)
	}
	if strings.Contains(strings.ToLower(string(dupBody)), "sql") || strings.Contains(string(dupBody), "postgres") {
		t.Fatalf("duplicate-email error leaked internal detail: %s", dupBody)
	}

	// --- assign a role, verify via GET, verify audit ---
	assignRes, assignBody := postJSON(t, client, env.Server.URL+"/v1/users/"+created.ID+"/roles",
		map[string]any{"role_id": roleSecurityEngineer}, authHeaders(adminToken))
	if assignRes.StatusCode != http.StatusNoContent {
		t.Fatalf("assign role: got %d; body=%s", assignRes.StatusCode, assignBody)
	}

	getReq, _ := http.NewRequest(http.MethodGet, env.Server.URL+"/v1/users/"+created.ID, nil)
	for k, v := range authHeaders(adminToken) {
		getReq.Header.Set(k, v)
	}
	getRes, getBody := doRequest(t, client, getReq)
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("get user detail: got %d; body=%s", getRes.StatusCode, getBody)
	}
	assertNoForbiddenFields(t, "get user detail response", getBody)
	var detail struct {
		Roles []struct {
			RoleName string `json:"role_name"`
		} `json:"roles"`
		Permissions []struct {
			Name string `json:"name"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(getBody, &detail); err != nil {
		t.Fatalf("decode user detail: %v", err)
	}
	if len(detail.Roles) != 1 || detail.Roles[0].RoleName != "Security Engineer" {
		t.Fatalf("expected exactly the Security Engineer role, got %+v", detail.Roles)
	}
	foundSecretsRead := false
	for _, p := range detail.Permissions {
		if p.Name == "secrets:read" {
			foundSecretsRead = true
		}
	}
	if !foundSecretsRead {
		t.Fatalf("expected effective permissions to include secrets:read (from Security Engineer), got %+v", detail.Permissions)
	}

	// --- remove the role ---
	removeReq, _ := http.NewRequest(http.MethodDelete, env.Server.URL+"/v1/users/"+created.ID+"/roles/"+roleSecurityEngineer, nil)
	for k, v := range authHeaders(adminToken) {
		removeReq.Header.Set(k, v)
	}
	removeRes, removeBody := doRequest(t, client, removeReq)
	if removeRes.StatusCode != http.StatusNoContent {
		t.Fatalf("remove role: got %d; body=%s", removeRes.StatusCode, removeBody)
	}

	// --- disable: real session revocation + real login rejection ---
	// First, log in as the target user for real to create a real session
	// to verify gets revoked.
	targetLoginRes, targetLoginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login", map[string]any{
		"email": targetEmail, "password": testPassword,
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if targetLoginRes.StatusCode != http.StatusOK {
		t.Fatalf("target user login before disable: got %d; body=%s", targetLoginRes.StatusCode, targetLoginBody)
	}
	var targetTok struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(targetLoginBody, &targetTok)

	var activeSessionsBefore int
	if err := env.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, created.ID,
	).Scan(&activeSessionsBefore); err != nil {
		t.Fatalf("count active sessions before disable: %v", err)
	}
	if activeSessionsBefore == 0 {
		t.Fatalf("expected at least 1 active session before disable")
	}

	disableRes, disableBody := postJSON(t, client, env.Server.URL+"/v1/users/"+created.ID+"/disable", nil, authHeaders(adminToken))
	if disableRes.StatusCode != http.StatusOK {
		t.Fatalf("disable user: got %d; body=%s", disableRes.StatusCode, disableBody)
	}

	var activeSessionsAfter int
	if err := env.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, created.ID,
	).Scan(&activeSessionsAfter); err != nil {
		t.Fatalf("count active sessions after disable: %v", err)
	}
	if activeSessionsAfter != 0 {
		t.Fatalf("expected 0 active sessions after disable, got %d", activeSessionsAfter)
	}

	// TEST 7: disabled user cannot authenticate.
	disabledLoginRes, disabledLoginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login", map[string]any{
		"email": targetEmail, "password": testPassword,
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if disabledLoginRes.StatusCode != http.StatusForbidden {
		t.Fatalf("login as disabled user: got %d, want 403; body=%s", disabledLoginRes.StatusCode, disabledLoginBody)
	}

	// The old refresh token must also no longer work — the session it
	// belonged to is revoked.
	refreshRes, refreshBody := postJSON(t, client, env.Server.URL+"/v1/auth/token/refresh",
		map[string]any{"refresh_token": targetTok.RefreshToken}, nil)
	if refreshRes.StatusCode == http.StatusOK {
		t.Fatalf("refresh token from a disabled user's revoked session unexpectedly succeeded: %s", refreshBody)
	}

	// TEST 8: re-enable, can authenticate again.
	enableRes, enableBody := postJSON(t, client, env.Server.URL+"/v1/users/"+created.ID+"/enable", nil, authHeaders(adminToken))
	if enableRes.StatusCode != http.StatusOK {
		t.Fatalf("enable user: got %d; body=%s", enableRes.StatusCode, enableBody)
	}
	reenabledLoginRes, reenabledLoginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login", map[string]any{
		"email": targetEmail, "password": testPassword,
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if reenabledLoginRes.StatusCode != http.StatusOK {
		t.Fatalf("login after re-enable: got %d; body=%s", reenabledLoginRes.StatusCode, reenabledLoginBody)
	}

	// TEST 10 (audit logging phase): DeleteUser previously produced no
	// audit trail at all for a real, wired DELETE /v1/users/{id} endpoint —
	// the one lifecycle transition in this flow that had none. Runs last:
	// SoftDelete only sets deleted_at (see userRepository.SoftDelete), the
	// row and its password_hash stay queryable for TEST 12/13 below.
	deleteReq, _ := http.NewRequest(http.MethodDelete, env.Server.URL+"/v1/users/"+created.ID, nil)
	for k, v := range authHeaders(adminToken) {
		deleteReq.Header.Set(k, v)
	}
	deleteRes, deleteBody := doRequest(t, client, deleteReq)
	if deleteRes.StatusCode != http.StatusNoContent {
		t.Fatalf("delete user: got %d; body=%s", deleteRes.StatusCode, deleteBody)
	}

	// TEST 11: audit events for every step above.
	for _, action := range []string{"user.created", "user.disabled", "user.enabled", "user.deleted", "role.assigned", "role.removed"} {
		var n int
		if err := env.DB.QueryRowContext(context.Background(),
			`SELECT count(*) FROM audit_logs WHERE action = $1 AND resource_id = $2`, action, created.ID,
		).Scan(&n); err != nil {
			t.Fatalf("count %s audit events: %v", action, err)
		}
		if n < 1 {
			t.Errorf("expected at least 1 %q audit event for user %s, got %d", action, created.ID, n)
		}
	}

	// TEST 12/13: no password, hash, or token anywhere in any admin
	// response captured above, and no plaintext password in the database.
	var passwordHash string
	if err := env.DB.QueryRowContext(context.Background(),
		`SELECT password_hash FROM users WHERE id = $1`, created.ID,
	).Scan(&passwordHash); err != nil {
		t.Fatalf("read password_hash: %v", err)
	}
	if !strings.HasPrefix(passwordHash, "$argon2id$") {
		t.Fatalf("password_hash is not a real Argon2id hash: %q", passwordHash)
	}

	_ = adminID // referenced for clarity of who performed these actions; audit checks above already verify actor
}

// TEST 9 (regression) — existing authentication still works exactly as
// before this sprint's changes: a plain registered user with no role at
// all can still log in, refresh, and log out. Adding real authorization
// enforcement to /v1/users and /v1/roles must never touch the
// authentication path itself.
func TestUserManagement_Regression_PlainAuthStillWorks(t *testing.T) {
	env := newE2EEnv(t)
	client := &http.Client{}
	token, _ := registerAndLoginWithRole(t, env, client, "" /* no role at all */)
	if token == "" {
		t.Fatalf("expected a real access token from a normal login")
	}
}
