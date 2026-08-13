package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/service"
)

// newTestSecretPolicyHandler wires a secretPolicyHandler against in-memory
// fakes, following secret_handler_test.go's own established convention for
// this package exactly (see newTestSecretHandler's own doc comment for the
// full rationale): no httptest server, no router, no middleware chain, and
// every request here carries NO claims in its context, so actorUserID(r)
// resolves to "" and every call is rejected by SecretPolicyService's own
// authorize() with entity.ErrForbidden before touching the fake repository.
// That's sufficient to exercise this file's own translation logic (JSON
// decoding, DTO validation, error-code mapping) — full authorized-call
// coverage (successful create/get/list/update/delete/assign, admin vs.
// non-admin) lives in test/e2e/secret_policies_test.go, which has real
// login infrastructure already built.
func newTestSecretPolicyHandler(t *testing.T) *secretPolicyHandler {
	t.Helper()
	repo := mocks.NewFakeSecretPolicyRepository()
	users := mocks.NewFakeUserRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := service.NewRBACService(rbacRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	svc := service.NewSecretPolicyService(repo, users, mocks.NewFakeServiceAccountRepository(), rbacSvc, auditTx)
	return &secretPolicyHandler{svc: svc}
}

func policyJSONRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-Id", "org-1")
	return req
}

// --- malformed JSON rejected before any service call ---

func TestSecretPolicyHandler_Create_MalformedJSON(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	rec := httptest.NewRecorder()
	h.create(rec, policyJSONRequest(http.MethodPost, "/v1/secret-policies", `{"name": "x", "rules": `))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec); code != "MALFORMED_REQUEST" {
		t.Errorf("error code = %q, want MALFORMED_REQUEST", code)
	}
}

func TestSecretPolicyHandler_Update_MalformedJSON(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := policyJSONRequest(http.MethodPut, "/v1/secret-policies/p1", `{"name": `)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.update(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestSecretPolicyHandler_Assign_MalformedJSON(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := policyJSONRequest(http.MethodPost, "/v1/secret-policies/p1/assignments", `{"role_id": `)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.assign(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// --- DTO-level validation rejected before any service call ---

func TestSecretPolicyHandler_Create_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty name", `{"name": "", "rules": [{"path_pattern": "dev/*", "actions": ["read"]}]}`},
		{"no rules", `{"name": "x", "rules": []}`},
		{"traversal path pattern", `{"name": "x", "rules": [{"path_pattern": "prod/../etc", "actions": ["read"]}]}`},
		{"embedded wildcard", `{"name": "x", "rules": [{"path_pattern": "prod/*/database", "actions": ["read"]}]}`},
		{"unknown action", `{"name": "x", "rules": [{"path_pattern": "dev/*", "actions": ["execute"]}]}`},
		{"missing actions", `{"name": "x", "rules": [{"path_pattern": "dev/*", "actions": []}]}`},
		{"bad effect", `{"name": "x", "rules": [{"path_pattern": "dev/*", "effect": "maybe", "actions": ["read"]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestSecretPolicyHandler(t)
			rec := httptest.NewRecorder()
			h.create(rec, policyJSONRequest(http.MethodPost, "/v1/secret-policies", tt.body))

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("status = %d, want %d (VALIDATION_ERROR); body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
			}
			if code := decodeErrorCode(t, rec); code != "VALIDATION_ERROR" {
				t.Errorf("error code = %q, want VALIDATION_ERROR", code)
			}
		})
	}
}

func TestSecretPolicyHandler_Update_EmptyNameRejected(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := policyJSONRequest(http.MethodPut, "/v1/secret-policies/p1", `{"name": ""}`)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.update(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestSecretPolicyHandler_Update_EmptyNonNilRulesRejected(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := policyJSONRequest(http.MethodPut, "/v1/secret-policies/p1", `{"name": "x", "rules": []}`)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.update(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestSecretPolicyHandler_Assign_MissingRoleID(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := policyJSONRequest(http.MethodPost, "/v1/secret-policies/p1/assignments", `{}`)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.assign(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

// --- defense-in-depth: no authenticated identity -> 403 for every route,
// the same "SecretPolicyService performs its own internal RBAC check"
// double-gate SecretService already has (see router.go's own comment on
// why secret-policies routes are registered the same way) ---

func TestSecretPolicyHandler_Create_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	rec := httptest.NewRecorder()
	h.create(rec, policyJSONRequest(http.MethodPost, "/v1/secret-policies", `{"name": "x", "rules": [{"path_pattern": "dev/*", "actions": ["read"]}]}`))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec); code != "FORBIDDEN" {
		t.Errorf("error code = %q, want FORBIDDEN", code)
	}
}

func TestSecretPolicyHandler_Get_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/secret-policies/p1", nil)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.get(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretPolicyHandler_List_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/secret-policies", nil)
	req.Header.Set("X-Organization-Id", "org-1")
	rec := httptest.NewRecorder()
	h.list(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretPolicyHandler_Update_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := policyJSONRequest(http.MethodPut, "/v1/secret-policies/p1", `{"name": "x", "rules": [{"path_pattern": "dev/*", "actions": ["read"]}]}`)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.update(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretPolicyHandler_Delete_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/secret-policies/p1", nil)
	req.Header.Set("X-Organization-Id", "org-1")
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.delete(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretPolicyHandler_Assign_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := policyJSONRequest(http.MethodPost, "/v1/secret-policies/p1/assignments", `{"role_id": "role-1"}`)
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.assign(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretPolicyHandler_Unassign_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/secret-policies/p1/assignments/role-1", nil)
	req.Header.Set("X-Organization-Id", "org-1")
	req.SetPathValue("policyId", "p1")
	req.SetPathValue("roleId", "role-1")
	rec := httptest.NewRecorder()
	h.unassign(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretPolicyHandler_ListAssignments_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/secret-policies/p1/assignments", nil)
	req.Header.Set("X-Organization-Id", "org-1")
	req.SetPathValue("policyId", "p1")
	rec := httptest.NewRecorder()
	h.listAssignments(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// --- no error response ever leaks internal detail ---

func TestSecretPolicyHandler_ErrorResponses_NeverLeakInternalDetail(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	rec := httptest.NewRecorder()
	h.create(rec, policyJSONRequest(http.MethodPost, "/v1/secret-policies", `{"name": "x", "rules": [{"path_pattern": "dev/*", "actions": ["read"]}]}`))

	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"sql", "postgres", "goroutine", "panic", ".go:", "internal/"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("error response body unexpectedly contains %q: %s", forbidden, rec.Body.String())
		}
	}
}

// sanity: decodeErrorCode (defined in secret_handler_test.go, this same
// package) works against this handler's error envelopes too, since both
// go through the identical writeServiceError/writeValidationError helpers.
func TestSecretPolicyHandler_ErrorEnvelope_IsWellFormed(t *testing.T) {
	h := newTestSecretPolicyHandler(t)
	rec := httptest.NewRecorder()
	h.create(rec, policyJSONRequest(http.MethodPost, "/v1/secret-policies", `{"name": "", "rules": []}`))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Errorf("response body missing top-level \"error\" key: %s", rec.Body.String())
	}
}
