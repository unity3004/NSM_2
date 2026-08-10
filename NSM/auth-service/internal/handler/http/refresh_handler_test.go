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
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

func generateTestEd25519PrivateKeyPEMForHandler(t *testing.T) string {
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

func newTestRefreshHandler(t *testing.T) (*refreshHandler, *mocks.FakeRefreshTokenRepository, *mocks.FakeSessionRepository) {
	t.Helper()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	sessionRepo := mocks.NewFakeSessionRepository()
	sessions := service.NewSessionService(sessionRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}

	keys, err := security.LoadSigningKeySet("test-key-1", generateTestEd25519PrivateKeyPEMForHandler(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	tokens := security.NewTokenService(keys, "auth-service", 10*time.Minute)

	svc := service.NewRefreshTokenService(service.RefreshTokenServiceDeps{
		RefreshTokens:       refreshTokens,
		Sessions:            sessions,
		Tokens:              tokens,
		AccessTokenAudience: "auth-service",
		AccessTokenTTL:      10 * time.Minute,
		RefreshTTL:          7 * 24 * time.Hour,
		AuditTx:             auditTx,
		AbuseProtection:     ratelimit.NoopAuthAbuseProtection{},
	})
	return &refreshHandler{svc: svc}, refreshTokens, sessionRepo
}

func seedRefreshTokenForHandler(t *testing.T, sessionRepo *mocks.FakeSessionRepository, refreshTokens *mocks.FakeRefreshTokenRepository) string {
	t.Helper()
	session := sessionRepo.Seed(&entity.Session{
		UserID:           "user-1",
		SessionTokenHash: util.NewUUID(),
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	raw, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	rt := &entity.RefreshToken{
		SessionID: session.ID,
		UserID:    "user-1",
		TokenHash: util.HashToken(raw),
		FamilyID:  util.NewUUID(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := refreshTokens.Create(t.Context(), rt); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return raw
}

func refreshHTTPRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// --- successful refresh: response shape ---

func TestRefreshHandler_Success(t *testing.T) {
	h, refreshTokens, sessionRepo := newTestRefreshHandler(t)
	raw := seedRefreshTokenForHandler(t, sessionRepo, refreshTokens)
	rec := httptest.NewRecorder()

	h.refresh(rec, refreshHTTPRequest(t, `{"refresh_token":"`+raw+`"}`))

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
	if got["refresh_token"] == nil || got["refresh_token"] == "" {
		t.Error("response has no refresh_token")
	}
	if got["refresh_token"] == raw {
		t.Error("response returned the same refresh token that was presented — rotation did not happen")
	}

	// The requirement this test exists to enforce, checked directly
	// against the actual bytes sent to a client: no database token hash
	// ever appears in the response.
	lower := strings.ToLower(rec.Body.String())
	if strings.Contains(lower, "hash") {
		t.Errorf("response body unexpectedly contains %q: %s", "hash", rec.Body.String())
	}
}

// --- malformed / invalid JSON ---

func TestRefreshHandler_InvalidJSON(t *testing.T) {
	h, _, _ := newTestRefreshHandler(t)
	rec := httptest.NewRecorder()

	h.refresh(rec, refreshHTTPRequest(t, `{"refresh_token": `)) // truncated

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (MALFORMED_REQUEST)", rec.Code, http.StatusBadRequest)
	}
}

// --- validation failure: missing refresh_token ---

func TestRefreshHandler_MissingRefreshToken(t *testing.T) {
	h, _, _ := newTestRefreshHandler(t)
	rec := httptest.NewRecorder()

	h.refresh(rec, refreshHTTPRequest(t, `{}`))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d (VALIDATION_ERROR)", rec.Code, http.StatusUnprocessableEntity)
	}
}

// --- rejections map to safe, generic responses ---

func TestRefreshHandler_UnknownToken(t *testing.T) {
	h, _, _ := newTestRefreshHandler(t)
	rec := httptest.NewRecorder()

	h.refresh(rec, refreshHTTPRequest(t, `{"refresh_token":"this-was-never-issued"}`))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	errObj, _ := got["error"].(map[string]any)
	if errObj["code"] != "TOKEN_EXPIRED" {
		t.Errorf("error code = %v, want TOKEN_EXPIRED", errObj["code"])
	}
}

func TestRefreshHandler_ReuseDetected(t *testing.T) {
	h, refreshTokens, sessionRepo := newTestRefreshHandler(t)
	raw := seedRefreshTokenForHandler(t, sessionRepo, refreshTokens)

	first := httptest.NewRecorder()
	h.refresh(first, refreshHTTPRequest(t, `{"refresh_token":"`+raw+`"}`))
	if first.Code != http.StatusOK {
		t.Fatalf("first refresh status = %d, want 200; body = %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	h.refresh(second, refreshHTTPRequest(t, `{"refresh_token":"`+raw+`"}`))
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("reused-token status = %d, want %d; body = %s", second.Code, http.StatusUnauthorized, second.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &got); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}
	errObj, _ := got["error"].(map[string]any)
	if errObj["code"] != "TOKEN_REUSE_DETECTED" {
		t.Errorf("error code = %v, want TOKEN_REUSE_DETECTED", errObj["code"])
	}
}

// --- internal failure: safe, generic response ---

func TestRefreshHandler_DatabaseFailureIsGeneric(t *testing.T) {
	h, refreshTokens, sessionRepo := newTestRefreshHandler(t)
	seedRefreshTokenForHandler(t, sessionRepo, refreshTokens)
	refreshTokens.FailNextGetByTokenHash = &fakeDBError{msg: "simulated database connection error: dial tcp 10.0.0.5:5432: connect: connection refused"}

	rec := httptest.NewRecorder()
	h.refresh(rec, refreshHTTPRequest(t, `{"refresh_token":"anything"}`))

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
}
