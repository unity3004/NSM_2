//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/dto"
)

type auditListResponse struct {
	Data []dto.AuditLogResponse `json:"data"`
	Page dto.PageMeta           `json:"page"`
}

func listAuditLogs(t *testing.T, env *e2eEnv, client *http.Client, token string, query url.Values) (*http.Response, auditListResponse) {
	t.Helper()
	u := env.Server.URL + "/v1/audit-logs"
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	res, body := doAuthed(t, client, http.MethodGet, u, token, nil, nil)
	var out auditListResponse
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode audit list response: %v; body = %s", err, body)
		}
	}
	return res, out
}

func findAuditEvent(entries []dto.AuditLogResponse, action string) (dto.AuditLogResponse, bool) {
	for _, e := range entries {
		if e.Action == action {
			return e, true
		}
	}
	return dto.AuditLogResponse{}, false
}

// --- 1/2. Successful and failed login each create an audit event,
// retrievable through the real admin API ---

func TestAuditE2E_Login_CreatesAuditEvents(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)
	_ = adminID

	suffix := uniqueSuffix(t)
	email := "audit-login-e2e-" + suffix + "@example.test"
	res, body := postJSON(t, client, env.Server.URL+"/v1/auth/register", map[string]any{
		"username": "audit-login-e2e-" + suffix, "email": email, "password": testPassword,
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d; body = %s", res.StatusCode, body)
	}
	var reg struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &reg)
	t.Cleanup(func() { env.DB.Exec(`DELETE FROM users WHERE id = $1`, reg.ID) })

	// Successful login.
	loginRes, loginBody := postJSON(t, client, env.Server.URL+"/v1/auth/login",
		dto.LoginRequest{Email: email, Password: testPassword}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login: status = %d; body = %s", loginRes.StatusCode, loginBody)
	}

	// Failed login (wrong password) — for the same user, so its
	// user.login event correctly names an actor_id.
	failRes, _ := postJSON(t, client, env.Server.URL+"/v1/auth/login",
		dto.LoginRequest{Email: email, Password: "definitely-the-wrong-password-1!"}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if failRes.StatusCode != http.StatusUnauthorized {
		t.Fatalf("failed login: status = %d, want 401", failRes.StatusCode)
	}

	actorID := reg.ID
	listRes, list := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {actorID}, "action": {"user.login"}, "limit": {"10"}})
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/audit-logs: status = %d", listRes.StatusCode)
	}
	var sawSuccess, sawFailure bool
	for _, e := range list.Data {
		if e.Action != "user.login" {
			continue
		}
		switch e.Result {
		case "success":
			sawSuccess = true
		case "failure":
			sawFailure = true
		}
	}
	if !sawSuccess {
		t.Error("no successful user.login audit event found")
	}
	if !sawFailure {
		t.Error("no failed user.login audit event found")
	}
}

// --- 3. Logout creates an audit event ---

func TestAuditE2E_Logout_CreatesAuditEvent(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	userID, userToken := registerPlainUser(t, env)

	logoutRes, logoutBody := postJSON(t, client, env.Server.URL+"/v1/auth/logout", struct{}{},
		map[string]string{"Authorization": "Bearer " + userToken, "X-Organization-Id": fixtureOrgID})
	if logoutRes.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /v1/auth/logout: status = %d; body = %s", logoutRes.StatusCode, logoutBody)
	}

	_, list := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {userID}, "action": {"auth.logout"}, "limit": {"10"}})
	if _, ok := findAuditEvent(list.Data, "auth.logout"); !ok {
		t.Error("no auth.logout audit event found for this user")
	}
}

// --- 4-7. Secret create/read/update/delete each create an audit event ---

func TestAuditE2E_SecretCRUD_CreatesAuditEvents(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "audit-e2e/" + suffix + "/db"

	createRes, createBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
		map[string]any{"path": path, "data": map[string]string{"k": "v1"}}, nil)
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("create: status = %d; body = %s", createRes.StatusCode, createBody)
	}
	getRes, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, adminToken, nil, nil)
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("read: status = %d", getRes.StatusCode)
	}
	updateRes, _ := doAuthed(t, client, http.MethodPut, env.Server.URL+"/v1/secrets/"+path, adminToken,
		map[string]any{"data": map[string]string{"k": "v2"}}, map[string]string{"If-Match": `"1"`})
	if updateRes.StatusCode != http.StatusOK {
		t.Fatalf("update: status = %d", updateRes.StatusCode)
	}
	deleteRes, _ := doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/secrets/"+path, adminToken, nil, nil)
	if deleteRes.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status = %d", deleteRes.StatusCode)
	}

	_, list := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {adminID}, "limit": {"100"}})
	for _, action := range []string{"secret.created", "secret.read", "secret.updated", "secret.deleted"} {
		if _, ok := findAuditEvent(list.Data, action); !ok {
			t.Errorf("no %s audit event found", action)
		}
	}
}

// --- 8. Authorization denial creates an audit event (the generic
// middleware-level authorization.denied, not only SecretService's own
// secret.access_denied) ---

func TestAuditE2E_AuthorizationDenial_CreatesAuditEvent(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)
	userID, userToken := registerPlainUser(t, env)

	// A plain user has no roles at all — users:read is denied.
	res, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/users", userToken, nil, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /v1/users as a plain user: status = %d, want 403", res.StatusCode)
	}

	action := "authorization.denied"
	_, list := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {userID}, "action": {action}, "limit": {"10"}})
	entry, ok := findAuditEvent(list.Data, action)
	if !ok {
		t.Fatal("no authorization.denied audit event found for the denied GET /v1/users request")
	}
	if entry.Result != "denied" {
		t.Errorf("Result = %q, want denied", entry.Result)
	}
}

// --- 9. Policy changes create audit events ---

func TestAuditE2E_PolicyChanges_CreateAuditEvents(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	createRes, createBody := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secret-policies", adminToken,
		map[string]any{"name": "audit-e2e-policy-" + suffix, "rules": []any{readRule("dev/"+suffix+"/*", "read")}}, nil)
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("create policy: status = %d; body = %s", createRes.StatusCode, createBody)
	}
	var created dto.SecretPolicyResponse
	_ = json.Unmarshal(createBody, &created)
	t.Cleanup(func() { env.DB.Exec(`DELETE FROM secret_policies WHERE id = $1`, created.ID) })

	deleteRes, deleteBody := doAuthed(t, client, http.MethodDelete, env.Server.URL+"/v1/secret-policies/"+created.ID, adminToken, nil, nil)
	if deleteRes.StatusCode != http.StatusNoContent {
		t.Fatalf("delete policy: status = %d; body = %s", deleteRes.StatusCode, deleteBody)
	}

	_, list := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {adminID}, "resource_id": {created.ID}, "limit": {"20"}})
	for _, action := range []string{"policy.created", "policy.deleted"} {
		if _, ok := findAuditEvent(list.Data, action); !ok {
			t.Errorf("no %s audit event found for policy %s", action, created.ID)
		}
	}
}

// --- 10. Audit access is itself audited ---

func TestAuditE2E_AuditAccess_IsItselfAudited(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)

	res, _ := listAuditLogs(t, env, client, adminToken, url.Values{"limit": {"5"}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/audit-logs: status = %d", res.StatusCode)
	}

	_, list := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {adminID}, "action": {"admin.audit.read"}, "limit": {"10"}})
	if _, ok := findAuditEvent(list.Data, "admin.audit.read"); !ok {
		t.Error("no admin.audit.read audit event was recorded for the earlier audit-log view")
	}
}

// --- 11-14. Sensitive material never appears anywhere in the audit API's
// own response, across a realistic flow that touches all four categories
// (a secret value, a password, and — indirectly — key material and
// tokens) ---

func TestAuditE2E_NeverLeaksSensitiveData(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "audit-e2e-leak/" + suffix + "/db"
	const secretValue = "SuperSecretPlaintextValue123"

	createRes, _ := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
		map[string]any{"path": path, "data": map[string]string{"password": secretValue}}, nil)
	if createRes.StatusCode != http.StatusCreated {
		t.Fatalf("create: status = %d", createRes.StatusCode)
	}
	getRes, _ := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, adminToken, nil, nil)
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("read: status = %d", getRes.StatusCode)
	}

	listRes, rawBody := doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/audit-logs?actor_id="+adminID+"&limit=100", adminToken, nil, nil)
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/audit-logs: status = %d", listRes.StatusCode)
	}

	lower := strings.ToLower(string(rawBody))
	for _, forbidden := range []string{
		strings.ToLower(secretValue),                               // item 11: plaintext secret value
		strings.ToLower(adminToken),                                // item 14: the bearer access token
		testPassword,                                               // item 13: a real account password
		"ciphertext", "wrapped_dek", "nonce", "auth_tag", "key_id", // item 12: encryption key material/metadata
	} {
		if strings.Contains(lower, strings.ToLower(forbidden)) {
			t.Errorf("GET /v1/audit-logs response unexpectedly contains %q", forbidden)
		}
	}
}

// --- 15. Unauthorized users cannot retrieve audit logs ---

func TestAuditE2E_UnauthorizedCannotListAuditLogs(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, userToken := registerPlainUser(t, env)

	res, _ := listAuditLogs(t, env, client, userToken, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("GET /v1/audit-logs as a plain user: status = %d, want 403", res.StatusCode)
	}

	unauthRes, _ := listAuditLogs(t, env, client, "", nil)
	if unauthRes.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /v1/audit-logs unauthenticated: status = %d, want 401", unauthRes.StatusCode)
	}
}

// --- 16. Results are paginated ---

func TestAuditE2E_Pagination(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)

	for i := 0; i < 4; i++ {
		path := "audit-e2e-page/" + suffix + "/" + string(rune('a'+i))
		res, body := doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
			map[string]any{"path": path, "data": map[string]string{"k": "v"}}, nil)
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("seed create %s: status = %d; body = %s", path, res.StatusCode, body)
		}
	}

	res, page1 := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {adminID}, "action": {"secret.created"}, "limit": {"2"}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("page 1: status = %d", res.StatusCode)
	}
	if len(page1.Data) != 2 {
		t.Fatalf("page 1 = %d entries, want 2", len(page1.Data))
	}
	if !page1.Page.HasMore || page1.Page.NextCursor == nil || *page1.Page.NextCursor == "" {
		t.Fatalf("page 1 PageMeta = %+v, want HasMore=true with a non-empty cursor (4 created, only 2 returned)", page1.Page)
	}

	res2, page2 := listAuditLogs(t, env, client, adminToken, url.Values{
		"actor_id": {adminID}, "action": {"secret.created"}, "limit": {"2"}, "cursor": {*page1.Page.NextCursor},
	})
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("page 2: status = %d", res2.StatusCode)
	}
	seen := map[string]bool{}
	for _, e := range append(page1.Data, page2.Data...) {
		if seen[e.ID] {
			t.Errorf("entry %s appeared on more than one page", e.ID)
		}
		seen[e.ID] = true
	}
	if len(seen) < 4 {
		t.Errorf("saw %d distinct secret.created entries across two pages, want at least 4", len(seen))
	}
}

// --- 17. Filters work correctly ---

func TestAuditE2E_FiltersWork(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "audit-e2e-filter/" + suffix + "/db"

	doAuthed(t, client, http.MethodPost, env.Server.URL+"/v1/secrets", adminToken,
		map[string]any{"path": path, "data": map[string]string{"k": "v"}}, nil)
	doAuthed(t, client, http.MethodGet, env.Server.URL+"/v1/secrets/"+path, adminToken, nil, nil)

	_, byAction := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {adminID}, "action": {"secret.read"}, "limit": {"50"}})
	for _, e := range byAction.Data {
		if e.Action != "secret.read" {
			t.Errorf("action filter leaked a non-matching row: %+v", e)
		}
	}
	if _, ok := findAuditEvent(byAction.Data, "secret.read"); !ok {
		t.Error("action filter unexpectedly returned zero secret.read rows")
	}

	_, byResult := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {adminID}, "result": {"success"}, "limit": {"50"}})
	for _, e := range byResult.Data {
		if e.Result != "success" {
			t.Errorf("result filter leaked a non-matching row: %+v", e)
		}
	}
}

// --- 18. SQL injection attempts through filters fail safely ---

func TestAuditE2E_SQLInjectionAttemptsFailSafely(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	payloads := []string{
		"'; DROP TABLE audit_logs; --",
		"' OR '1'='1",
		"1; DELETE FROM audit_logs WHERE 1=1; --",
		"' UNION SELECT * FROM users --",
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			for _, param := range []string{"actor_id", "resource_id", "action", "request_id", "cursor"} {
				res, body := listAuditLogs(t, env, client, adminToken, url.Values{param: {payload}, "limit": {"5"}})
				if res.StatusCode == http.StatusInternalServerError {
					t.Errorf("param=%s payload=%q: status = 500 — possible injection or unhandled input; body = %+v", param, payload, body)
				}
				if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusUnprocessableEntity {
					t.Errorf("param=%s payload=%q: status = %d, want 200 (safely empty/filtered) or 422 (rejected), never anything else", param, payload, res.StatusCode)
				}
			}
		})
	}

	// The table must still be intact and queryable after every attempt above.
	sanityRes, sanity := listAuditLogs(t, env, client, adminToken, url.Values{"limit": {"1"}})
	if sanityRes.StatusCode != http.StatusOK {
		t.Fatalf("sanity check after injection attempts: status = %d — audit_logs may have been damaged", sanityRes.StatusCode)
	}
	_ = sanity
}

// --- 19. Audit records cannot be modified through normal application APIs ---

func TestAuditE2E_NoModifyAPIExists(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	_, adminToken := bootstrapAdminAndLogin(t, env)

	for _, req := range []struct{ method, path string }{
		{http.MethodPut, "/v1/audit-logs"},
		{http.MethodPatch, "/v1/audit-logs"},
		{http.MethodDelete, "/v1/audit-logs"},
		{http.MethodPost, "/v1/audit-logs"},
		{http.MethodPut, "/v1/audit-logs/1"},
		{http.MethodDelete, "/v1/audit-logs/1"},
	} {
		t.Run(req.method+" "+req.path, func(t *testing.T) {
			res, _ := doAuthed(t, client, req.method, env.Server.URL+req.path, adminToken, map[string]any{"action": "tampered"}, nil)
			if res.StatusCode >= 200 && res.StatusCode < 300 {
				t.Errorf("%s %s unexpectedly succeeded with status %d — no mutating audit-log API may exist", req.method, req.path, res.StatusCode)
			}
		})
	}
}

// --- 20. Request IDs correlate events correctly ---

func TestAuditE2E_RequestIDsCorrelateEvents(t *testing.T) {
	env := newSecretsE2EEnv(t)
	client := env.Server.Client()
	adminID, adminToken := bootstrapAdminAndLogin(t, env)
	suffix := uniqueSuffix(t)
	path := "audit-e2e-reqid/" + suffix + "/db"
	customRequestID := "req-e2e-correlation-" + suffix

	req, err := http.NewRequest(http.MethodPost, env.Server.URL+"/v1/secrets", strings.NewReader(
		`{"path": "`+path+`", "data": {"k": "v"}}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Organization-Id", fixtureOrgID)
	req.Header.Set("X-Request-Id", customRequestID)
	res, body := doRequest(t, client, req)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create with custom X-Request-Id: status = %d; body = %s", res.StatusCode, body)
	}
	if got := res.Header.Get("X-Request-Id"); got != customRequestID {
		t.Errorf("response X-Request-Id = %q, want the caller-supplied %q echoed back", got, customRequestID)
	}

	_, list := listAuditLogs(t, env, client, adminToken, url.Values{"actor_id": {adminID}, "request_id": {customRequestID}, "limit": {"10"}})
	entry, ok := findAuditEvent(list.Data, "secret.created")
	if !ok {
		t.Fatal("no secret.created event found filtered by the custom request_id")
	}
	if entry.RequestID == nil || *entry.RequestID != customRequestID {
		t.Errorf("returned event RequestID = %v, want %q", entry.RequestID, customRequestID)
	}
}
