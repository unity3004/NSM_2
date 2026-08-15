package http

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/middleware"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
)

func newTestLogoutHandler(t *testing.T) (*logoutHandler, *mocks.FakeSessionRepository) {
	t.Helper()
	sessionRepo := mocks.NewFakeSessionRepository()
	sessions := service.NewSessionService(sessionRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
	svc := service.NewLogoutService(service.LogoutServiceDeps{Sessions: sessions, AuditTx: auditTx})
	return &logoutHandler{svc: svc}, sessionRepo
}

func logoutRequestWithIdentity(t *testing.T, identity middleware.AuthenticatedIdentity) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout/current", nil)
	return req.WithContext(middleware.WithIdentity(req.Context(), identity))
}

// --- successful logout ---

func TestLogoutHandler_Success(t *testing.T) {
	h, sessionRepo := newTestLogoutHandler(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})

	rec := httptest.NewRecorder()
	h.logout(rec, logoutRequestWithIdentity(t, middleware.AuthenticatedIdentity{Subject: "user-1", SessionID: session.ID, TokenID: "jti-1"}))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("response body = %q, want empty", rec.Body.String())
	}

	stored, err := sessionRepo.GetByID(t.Context(), session.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if stored.RevokedAt == nil {
		t.Error("session was not revoked")
	}
}

// --- missing authentication context ---

func TestLogoutHandler_MissingIdentity(t *testing.T) {
	h, _ := newTestLogoutHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout/current", nil) // no identity ever placed on context

	h.logout(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (UNAUTHENTICATED)", rec.Code, http.StatusUnauthorized)
	}
}

// --- missing session identity in an otherwise-authenticated request ---

// TestLogoutHandler_MissingSessionID covers the defensive case: an
// AuthenticatedIdentity with no SessionID, which a real
// middleware.Authenticate chain no longer produces for a normal user
// access token (security.AccessTokenClaims now carries `sid` — see that
// type's own doc comment) but which a future issuer without a session to
// name (e.g. a service-account token) legitimately still could —
// requirement #23: this must be a safe 401, never a crash or a
// silently-wrong revocation.
func TestLogoutHandler_MissingSessionID(t *testing.T) {
	h, _ := newTestLogoutHandler(t)
	rec := httptest.NewRecorder()

	h.logout(rec, logoutRequestWithIdentity(t, middleware.AuthenticatedIdentity{Subject: "user-1", SessionID: "", TokenID: "jti-1"}))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (UNAUTHENTICATED)", rec.Code, http.StatusUnauthorized)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	errObj, _ := got["error"].(map[string]any)
	if errObj["code"] != "UNAUTHENTICATED" {
		t.Errorf("error code = %v, want UNAUTHENTICATED", errObj["code"])
	}
}

// --- cross-user rejection ---

func TestLogoutHandler_CrossUserSessionRejected(t *testing.T) {
	h, sessionRepo := newTestLogoutHandler(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})

	rec := httptest.NewRecorder()
	h.logout(rec, logoutRequestWithIdentity(t, middleware.AuthenticatedIdentity{Subject: "user-2", SessionID: session.ID, TokenID: "jti-1"}))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	stored, err := sessionRepo.GetByID(t.Context(), session.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if stored.RevokedAt != nil {
		t.Error("a cross-user logout request actually revoked the session")
	}
}

// --- idempotency ---

func TestLogoutHandler_Idempotent(t *testing.T) {
	h, sessionRepo := newTestLogoutHandler(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})
	identity := middleware.AuthenticatedIdentity{Subject: "user-1", SessionID: session.ID, TokenID: "jti-1"}

	first := httptest.NewRecorder()
	h.logout(first, logoutRequestWithIdentity(t, identity))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first logout status = %d, want %d", first.Code, http.StatusNoContent)
	}

	second := httptest.NewRecorder()
	h.logout(second, logoutRequestWithIdentity(t, identity))
	if second.Code != http.StatusNoContent {
		t.Errorf("second logout status = %d, want %d (idempotent)", second.Code, http.StatusNoContent)
	}
}

// --- internal failure: safe, generic response ---

func TestLogoutHandler_DatabaseFailureIsGeneric(t *testing.T) {
	h, sessionRepo := newTestLogoutHandler(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})
	sessionRepo.FailNextRevoke = &fakeDBError{msg: "simulated database connection error: dial tcp 10.0.0.5:5432: connect: connection refused"}

	rec := httptest.NewRecorder()
	h.logout(rec, logoutRequestWithIdentity(t, middleware.AuthenticatedIdentity{Subject: "user-1", SessionID: session.ID, TokenID: "jti-1"}))

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
	if msg != "An unexpected error occurred." {
		t.Errorf("error message = %q, want the fixed generic INTERNAL_ERROR message", msg)
	}
}

// --- full middleware chain: unauthenticated requests never reach the handler ---

func generateTestEd25519PrivateKeyPEMForLogout(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestLogoutHandler_UnauthenticatedRequestRejected is the one test that
// runs through the real middleware.Authenticate chain rather than
// injecting an identity directly — proving the route actually requires
// authentication, not just that the handler behaves if it's skipped.
func TestLogoutHandler_UnauthenticatedRequestRejected(t *testing.T) {
	h, _ := newTestLogoutHandler(t)
	keys, err := security.LoadSigningKeySet("key-1", generateTestEd25519PrivateKeyPEMForLogout(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	tokens := security.NewTokenService(keys, "auth-service", 10*time.Minute)
	chain := middleware.Authenticate(tokens, "auth-service")(http.HandlerFunc(h.logout))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout/current", nil) // no Authorization header at all
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — the request must never reach the handler", rec.Code, http.StatusUnauthorized)
	}
}
