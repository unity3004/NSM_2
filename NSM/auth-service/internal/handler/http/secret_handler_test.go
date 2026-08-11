package http

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/secrets"
	"github.com/acme/auth-service/internal/service"
)

// newTestSecretHandler wires a secretHandler against the same in-memory
// fakes internal/service's own secret_service_test.go uses, plus a real
// secrets.EncryptionService (real AES-256-GCM, a fresh test-only key) —
// following register_test.go's established convention for this package:
// no httptest server, no router, no middleware chain, just the handler
// method called directly with a real *http.Request.
//
// Every test in this file calls the handler with NO claims in the
// request context (see register_test.go's own doc comment on why this
// package's tests don't fabricate middleware.ClaimsFromContext values —
// there is no exported way to do that from outside internal/middleware,
// and no precedent anywhere in this codebase for adding one). That means
// actorUserID(r) resolves to "" for every request here, which
// SecretService's own authorize() treats as "no authenticated identity"
// and rejects with entity.ErrForbidden (403) — see this file's
// "_NoClaims_" tests, which exist specifically to prove that
// defense-in-depth path, not to exercise a successfully authorized call.
// Full authorized-call coverage (successful create/read/update/delete,
// RBAC-permitted vs. not, real audit trail) lives in test/e2e/secrets_test.go,
// which has real login infrastructure already built — the same split of
// responsibility this package's other handler tests already follow.
func newTestSecretHandler(t *testing.T) *secretHandler {
	t.Helper()
	repo := mocks.NewFakeSecretRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := service.NewRBACService(rbacRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	provider, err := secrets.NewDevKeyProvider("test-key-1", base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewDevKeyProvider: %v", err)
	}
	enc := secrets.NewEncryptionService(provider)

	svc := service.NewSecretService(repo, enc, rbacSvc, auditTx)
	return &secretHandler{svc: svc}
}

func jsonRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-Id", "org-1")
	return req
}

func decodeErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var got struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v (body = %s)", err, rec.Body.String())
	}
	return got.Error.Code
}

// --- 13. Malformed JSON rejected ---

func TestSecretsHandler_Create_MalformedJSON(t *testing.T) {
	h := newTestSecretHandler(t)
	rec := httptest.NewRecorder()

	h.create(rec, jsonRequest(http.MethodPost, "/v1/secrets", `{"path": "prod/db", "data": `)) // truncated

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec); code != "MALFORMED_REQUEST" {
		t.Errorf("error code = %q, want MALFORMED_REQUEST", code)
	}
}

func TestSecretsHandler_Update_MalformedJSON(t *testing.T) {
	h := newTestSecretHandler(t)
	req := jsonRequest(http.MethodPut, "/v1/secrets/prod/db", `{"data": `)
	req.Header.Set("If-Match", `"1"`)
	rec := httptest.NewRecorder()

	h.update(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// --- 14. Oversized request rejected ---

func TestSecretsHandler_Create_OversizedBody(t *testing.T) {
	h := newTestSecretHandler(t)
	// One field alone exceeds maxSecretRequestBodyBytes (256 KiB).
	huge := strings.Repeat("A", maxSecretRequestBodyBytes+1024)
	body := `{"path": "prod/db", "data": {"value": "` + huge + `"}}`
	rec := httptest.NewRecorder()

	h.create(rec, jsonRequest(http.MethodPost, "/v1/secrets", body))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (oversized body); body length = %d", rec.Code, http.StatusBadRequest, rec.Body.Len())
	}
}

// --- Content-Type validation ---

func TestSecretsHandler_Create_WrongContentType(t *testing.T) {
	h := newTestSecretHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(`{"path":"prod/db","data":{"k":"v"}}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Organization-Id", "org-1")
	rec := httptest.NewRecorder()

	h.create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestSecretsHandler_Create_MissingContentType(t *testing.T) {
	h := newTestSecretHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/secrets", strings.NewReader(`{"path":"prod/db","data":{"k":"v"}}`))
	req.Header.Set("X-Organization-Id", "org-1")
	rec := httptest.NewRecorder()

	h.create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for a missing Content-Type", rec.Code, http.StatusBadRequest)
	}
}

// --- 11 & 12. Invalid path / path traversal rejected (DTO-level, on Create) ---

func TestSecretsHandler_Create_InvalidPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"parent traversal segment", "../etc/passwd"},
		{"embedded traversal segment", "prod/../secret"},
		{"double slash / empty segment", "prod//db"},
		{"disallowed characters", "prod/db;DROP TABLE secrets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestSecretHandler(t)
			body, err := json.Marshal(map[string]any{"path": tt.path, "data": map[string]string{"k": "v"}})
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			rec := httptest.NewRecorder()

			h.create(rec, jsonRequest(http.MethodPost, "/v1/secrets", string(body)))

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("path %q: status = %d, want %d (VALIDATION_ERROR); body = %s", tt.path, rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
			}
			if code := decodeErrorCode(t, rec); code != "VALIDATION_ERROR" {
				t.Errorf("path %q: error code = %q, want VALIDATION_ERROR", tt.path, code)
			}
		})
	}
}

// --- Empty payload rejected ---

func TestSecretsHandler_Create_EmptyPayload(t *testing.T) {
	h := newTestSecretHandler(t)
	rec := httptest.NewRecorder()

	h.create(rec, jsonRequest(http.MethodPost, "/v1/secrets", `{"path": "prod/db", "data": {}}`))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestSecretsHandler_Update_EmptyPayload(t *testing.T) {
	h := newTestSecretHandler(t)
	req := jsonRequest(http.MethodPut, "/v1/secrets/prod/db", `{"data": {}}`)
	req.Header.Set("If-Match", `"1"`)
	rec := httptest.NewRecorder()

	h.update(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

// --- Update requires a valid If-Match ---

func TestSecretsHandler_Update_MissingIfMatch(t *testing.T) {
	h := newTestSecretHandler(t)
	req := jsonRequest(http.MethodPut, "/v1/secrets/prod/db", `{"data": {"k": "v"}}`)
	req.SetPathValue("path", "prod/db")
	rec := httptest.NewRecorder()

	h.update(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestSecretsHandler_Update_MalformedIfMatch(t *testing.T) {
	for _, val := range []string{"abc", "0", "-1", ""} {
		t.Run(val, func(t *testing.T) {
			h := newTestSecretHandler(t)
			req := jsonRequest(http.MethodPut, "/v1/secrets/prod/db", `{"data": {"k": "v"}}`)
			if val != "" {
				req.Header.Set("If-Match", val)
			}
			rec := httptest.NewRecorder()

			h.update(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("If-Match=%q: status = %d, want %d", val, rec.Code, http.StatusUnprocessableEntity)
			}
		})
	}
}

// --- Invalid version query parameter rejected ---

func TestSecretsHandler_Get_InvalidVersionParam(t *testing.T) {
	for _, val := range []string{"abc", "0", "-1", "1.5"} {
		t.Run(val, func(t *testing.T) {
			h := newTestSecretHandler(t)
			req := httptest.NewRequest(http.MethodGet, "/v1/secrets/prod/db?version="+val, nil)
			req.Header.Set("X-Organization-Id", "org-1")
			req.SetPathValue("path", "prod/db")
			rec := httptest.NewRecorder()

			h.get(rec, req)

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("version=%q: status = %d, want %d", val, rec.Code, http.StatusUnprocessableEntity)
			}
		})
	}
}

// --- Defense-in-depth: no authenticated identity -> 403, never a crash
// or data exposure, even though in real operation
// middleware.RequirePermission would already have rejected such a
// request with 401 before the handler ever ran. See newTestSecretHandler's
// own doc comment for why this file cannot simulate that 401 path
// directly, and why these tests instead verify the service's own
// second-layer check. ---

func TestSecretsHandler_Create_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretHandler(t)
	rec := httptest.NewRecorder()

	h.create(rec, jsonRequest(http.MethodPost, "/v1/secrets", `{"path": "prod/db", "data": {"k": "v"}}`))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec); code != "FORBIDDEN" {
		t.Errorf("error code = %q, want FORBIDDEN", code)
	}
}

func TestSecretsHandler_Get_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/secrets/prod/db", nil)
	req.Header.Set("X-Organization-Id", "org-1")
	req.SetPathValue("path", "prod/db")
	rec := httptest.NewRecorder()

	h.get(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretsHandler_List_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/secrets", nil)
	req.Header.Set("X-Organization-Id", "org-1")
	rec := httptest.NewRecorder()

	h.list(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretsHandler_Delete_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretHandler(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/secrets/prod/db", nil)
	req.Header.Set("X-Organization-Id", "org-1")
	req.SetPathValue("path", "prod/db")
	rec := httptest.NewRecorder()

	h.delete(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestSecretsHandler_Update_NoClaims_Returns403(t *testing.T) {
	h := newTestSecretHandler(t)
	req := jsonRequest(http.MethodPut, "/v1/secrets/prod/db", `{"data": {"k": "v"}}`)
	req.Header.Set("If-Match", `"1"`)
	req.SetPathValue("path", "prod/db")
	rec := httptest.NewRecorder()

	h.update(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// --- No error response ever leaks internal detail ---

func TestSecretsHandler_ErrorResponses_NeverLeakInternalDetail(t *testing.T) {
	h := newTestSecretHandler(t)
	rec := httptest.NewRecorder()
	h.create(rec, jsonRequest(http.MethodPost, "/v1/secrets", `{"path": "prod/db", "data": {"k": "v"}}`))

	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"sql", "postgres", "goroutine", "panic", ".go:", "internal/"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("error response body unexpectedly contains %q: %s", forbidden, rec.Body.String())
		}
	}
}
