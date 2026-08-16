package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
)

// newTestUserHandler wires a userHandler against the same in-memory fakes
// internal/service's own tests use — this file is the codebase's first
// handler-level test, so it deliberately reuses that existing pattern
// rather than introducing a second one: no httptest server, no router, no
// middleware chain — just the handler function itself, called directly
// with a real *http.Request built by httptest.NewRequest, which is enough
// to prove decodeJSON/Validate/response-shape behavior without needing
// this file to also re-test Recover/RequestID/Logging/CORS.
func newTestUserHandler(t *testing.T) (*userHandler, *mocks.FakeUserRepository, *mocks.FakeAuditLogRepository) {
	t.Helper()
	users := mocks.NewFakeUserRepository()
	audit := mocks.NewFakeAuditLogRepository()
	passwords := security.NewPasswordService(security.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32,
	})
	svc := service.NewUserService(users, passwords, mocks.FakeRegistrationTx(users, audit))
	return &userHandler{svc: svc}, users, audit
}

func registerRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-Id", "org-1")
	return req
}

// --- successful registration: response shape ---

func TestRegisterHandler_Success(t *testing.T) {
	h, _, _ := newTestUserHandler(t)
	rec := httptest.NewRecorder()

	h.register(rec, registerRequest(t, `{"username":"marcus.webb","email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v (body = %s)", err, rec.Body.String())
	}
	if got["username"] != "marcus.webb" {
		t.Errorf("response username = %v, want %q", got["username"], "marcus.webb")
	}
	if got["email"] != "marcus.webb@acme.com" {
		t.Errorf("response email = %v, want %q", got["email"], "marcus.webb@acme.com")
	}
	if got["id"] == nil || got["id"] == "" {
		t.Error("response has no id")
	}

	// The requirement this test exists to enforce, checked directly against
	// the actual bytes sent to a client — not just against the Go struct's
	// field list (see dto.TestRegisterResponse_NeverEncodesPasswordFields
	// for that check) — no access/refresh token either: registration must
	// not auto-login.
	lower := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"password", "hash", "access_token", "refresh_token"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("response body unexpectedly contains %q: %s", forbidden, rec.Body.String())
		}
	}
}

// --- malformed / invalid JSON ---

func TestRegisterHandler_InvalidJSON(t *testing.T) {
	h, _, _ := newTestUserHandler(t)
	rec := httptest.NewRecorder()

	h.register(rec, registerRequest(t, `{"username": "marcus.webb", "email": `)) // truncated

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (MALFORMED_REQUEST)", rec.Code, http.StatusBadRequest)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	errObj, _ := got["error"].(map[string]any)
	if errObj["code"] != "MALFORMED_REQUEST" {
		t.Errorf("error code = %v, want MALFORMED_REQUEST", errObj["code"])
	}
}

// --- validation failure: missing required field ---

func TestRegisterHandler_MissingUsername(t *testing.T) {
	h, _, _ := newTestUserHandler(t)
	rec := httptest.NewRecorder()

	h.register(rec, registerRequest(t, `{"email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d (VALIDATION_ERROR)", rec.Code, http.StatusUnprocessableEntity)
	}
}

// --- duplicate account: generic response, no enumeration hint ---

func TestRegisterHandler_DuplicateAccount(t *testing.T) {
	h, _, _ := newTestUserHandler(t)

	first := httptest.NewRecorder()
	h.register(first, registerRequest(t, `{"username":"marcus.webb","email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))
	if first.Code != http.StatusCreated {
		t.Fatalf("first registration status = %d, want 201; body = %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	h.register(second, registerRequest(t, `{"username":"someone-else","email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))

	if second.Code != http.StatusConflict {
		t.Fatalf("duplicate-email status = %d, want %d; body = %s", second.Code, http.StatusConflict, second.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &got); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	errObj, _ := got["error"].(map[string]any)
	if errObj["code"] != "CONFLICT" {
		t.Errorf("error code = %v, want CONFLICT", errObj["code"])
	}
	// The anti-enumeration requirement, checked directly: the response must
	// not say which field collided.
	msg, _ := errObj["message"].(string)
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "email") || strings.Contains(lower, "username") {
		t.Errorf("error message = %q, must not name which field was a duplicate", msg)
	}
}

// --- internal failure: safe, generic response ---

func TestRegisterHandler_InternalErrorIsGeneric(t *testing.T) {
	h, _, audit := newTestUserHandler(t)
	// Force the kind of failure a real database outage would produce —
	// UserService.Register has no specific mapping for it, so it must
	// fall to writeServiceError's default branch. FailNext is the same
	// fault-injection point internal/service/user_service_test.go's
	// "no partial state" test uses; reusing it here (rather than a
	// speculative I/O trick) is what makes this test actually prove what
	// its name claims.
	audit.FailNext = errors.New("simulated database connection error: dial tcp 10.0.0.5:5432: connect: connection refused")

	rec := httptest.NewRecorder()
	h.register(rec, registerRequest(t, `{"username":"marcus.webb","email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	errObj, _ := got["error"].(map[string]any)
	if errObj["code"] != "INTERNAL_ERROR" {
		t.Errorf("error code = %v, want INTERNAL_ERROR", errObj["code"])
	}
	// The requirement this test exists to enforce: the real error text
	// (the simulated dial-tcp/connection-refused detail above) must never
	// reach the response body — only the generic message writeServiceError
	// always uses for its default branch.
	msg, _ := errObj["message"].(string)
	if strings.Contains(msg, "tcp") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "10.0.0.5") {
		t.Errorf("error message leaked internal detail: %q", msg)
	}
	if msg != "An unexpected error occurred." {
		t.Errorf("error message = %q, want the fixed generic INTERNAL_ERROR message", msg)
	}
}
