package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// newTestAuthHandler wires an authHandler against the same in-memory fakes
// internal/service/auth_service_test.go uses — see that file's
// newTestAuthService for why the audit fake is a plain pass-through rather
// than register_test.go's newTestUserHandler's transactional
// FakeRegistrationTx.
func newTestAuthHandler(t *testing.T) (*authHandler, *mocks.FakeUserRepository) {
	t.Helper()
	users := mocks.NewFakeUserRepository()
	sessions := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	loginHistory := mocks.NewFakeLoginHistoryRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
	passwords := security.NewPasswordService(security.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32,
	})

	svc := service.NewAuthService(service.AuthServiceDeps{
		Users:         users,
		Sessions:      sessions,
		RefreshTokens: refreshTokens,
		LoginHistory:  loginHistory,
		Tokens:        util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		Passwords:     passwords,
		RefreshTTL:    30 * 24 * time.Hour,
		AuditTx:       auditTx,
	})
	return &authHandler{svc: svc}, users
}

func seedLoginUser(t *testing.T, users *mocks.FakeUserRepository, email, password string) *entity.User {
	t.Helper()
	passwords := security.NewPasswordService(security.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32,
	})
	hash, err := passwords.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return users.Seed(&entity.User{
		OrganizationID: "org-1",
		Email:          email,
		PasswordHash:   &hash,
		Status:         entity.UserStatusActive,
	})
}

func loginRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-Id", "org-1")
	return req
}

// --- successful login: response shape ---

func TestLoginHandler_Success(t *testing.T) {
	h, users := newTestAuthHandler(t)
	seedLoginUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")
	rec := httptest.NewRecorder()

	h.login(rec, loginRequest(t, `{"email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v (body = %s)", err, rec.Body.String())
	}
	if got["access_token"] == nil || got["access_token"] == "" {
		t.Error("response has no access_token")
	}

	// The requirement this test exists to enforce, checked directly against
	// the actual bytes sent to a client: never a password or a stored hash.
	lower := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"password", "hash"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("response body unexpectedly contains %q: %s", forbidden, rec.Body.String())
		}
	}
}

// --- malformed / invalid JSON ---

func TestLoginHandler_InvalidJSON(t *testing.T) {
	h, _ := newTestAuthHandler(t)
	rec := httptest.NewRecorder()

	h.login(rec, loginRequest(t, `{"email": "marcus.webb@acme.com", "password": `)) // truncated

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

// --- validation failure: missing password ---

func TestLoginHandler_MissingPassword(t *testing.T) {
	h, _ := newTestAuthHandler(t)
	rec := httptest.NewRecorder()

	h.login(rec, loginRequest(t, `{"email":"marcus.webb@acme.com"}`))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d (VALIDATION_ERROR)", rec.Code, http.StatusUnprocessableEntity)
	}
}

// --- validation failure: invalid email ---

func TestLoginHandler_InvalidEmail(t *testing.T) {
	h, _ := newTestAuthHandler(t)
	rec := httptest.NewRecorder()

	h.login(rec, loginRequest(t, `{"email":"not-an-email","password":"whatever-password"}`))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d (VALIDATION_ERROR)", rec.Code, http.StatusUnprocessableEntity)
	}
}

// --- anti-enumeration: unknown email vs. wrong password are indistinguishable ---

func TestLoginHandler_UnknownEmailAndWrongPasswordLookIdentical(t *testing.T) {
	h, users := newTestAuthHandler(t)
	seedLoginUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	unknown := httptest.NewRecorder()
	h.login(unknown, loginRequest(t, `{"email":"nobody@acme.com","password":"whatever-password"}`))

	wrongPassword := httptest.NewRecorder()
	h.login(wrongPassword, loginRequest(t, `{"email":"marcus.webb@acme.com","password":"wrong-password"}`))

	if unknown.Code != http.StatusUnauthorized || wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("status codes = %d / %d, want both %d", unknown.Code, wrongPassword.Code, http.StatusUnauthorized)
	}
	// Byte-identical bodies are the actual anti-enumeration proof: nothing
	// about which case occurred may leak through response shape or wording.
	if unknown.Body.String() != wrongPassword.Body.String() {
		t.Errorf("responses differ:\nunknown email:   %s\nwrong password:  %s", unknown.Body.String(), wrongPassword.Body.String())
	}
}

// --- disabled account ---

func TestLoginHandler_DisabledAccount(t *testing.T) {
	h, users := newTestAuthHandler(t)
	u := seedLoginUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")
	u.Status = entity.UserStatusDisabled

	rec := httptest.NewRecorder()
	h.login(rec, loginRequest(t, `{"email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (ACCOUNT_DISABLED)", rec.Code, http.StatusForbidden)
	}
}

// --- internal failure: safe, generic response ---

func TestLoginHandler_DatabaseFailureIsGeneric(t *testing.T) {
	h, users := newTestAuthHandler(t)
	dbErr := "simulated database connection error: dial tcp 10.0.0.5:5432: connect: connection refused"
	users.FailNextGetByEmail = &fakeDBError{msg: dbErr}

	rec := httptest.NewRecorder()
	h.login(rec, loginRequest(t, `{"email":"marcus.webb@acme.com","password":"Tr0ub4dor&3xample!"}`))

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
	msg, _ := errObj["message"].(string)
	if strings.Contains(msg, "tcp") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "10.0.0.5") {
		t.Errorf("error message leaked internal detail: %q", msg)
	}
	if msg != "An unexpected error occurred." {
		t.Errorf("error message = %q, want the fixed generic INTERNAL_ERROR message", msg)
	}
}

// fakeDBError stands in for a real driver error (e.g. *net.OpError wrapped
// by database/sql) — only its Error() text matters for this test, which
// checks that text never reaches the client.
type fakeDBError struct{ msg string }

func (e *fakeDBError) Error() string { return e.msg }
