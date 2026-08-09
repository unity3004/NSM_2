package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
)

func newTestLogoutService(t *testing.T) (*LogoutService, *mocks.FakeSessionRepository, *mocks.FakeAuditLogRepository) {
	t.Helper()
	sessionRepo := mocks.NewFakeSessionRepository()
	sessions := NewSessionService(sessionRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
	svc := NewLogoutService(LogoutServiceDeps{Sessions: sessions, AuditTx: auditTx})
	return svc, sessionRepo, audit
}

// --- successful logout ---

func TestLogoutService_Logout_Success(t *testing.T) {
	svc, sessionRepo, _ := newTestLogoutService(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})

	if err := svc.Logout(t.Context(), "user-1", session.ID, LoginMeta{IPAddress: "203.0.113.42"}); err != nil {
		t.Fatalf("Logout() error = %v, want nil", err)
	}

	stored, err := sessionRepo.GetByID(t.Context(), session.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if stored.RevokedAt == nil {
		t.Error("session was not revoked")
	}
	if stored.RevokedReason == nil || *stored.RevokedReason != entity.RevocationLogout {
		t.Errorf("RevokedReason = %v, want %q", stored.RevokedReason, entity.RevocationLogout)
	}
	if stored.IsActive(time.Now()) {
		t.Error("a revoked session reports IsActive() = true")
	}
}

// --- idempotency ---

func TestLogoutService_Logout_Idempotent(t *testing.T) {
	svc, sessionRepo, _ := newTestLogoutService(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})

	if err := svc.Logout(t.Context(), "user-1", session.ID, LoginMeta{}); err != nil {
		t.Fatalf("first Logout() error = %v, want nil", err)
	}
	if err := svc.Logout(t.Context(), "user-1", session.ID, LoginMeta{}); err != nil {
		t.Errorf("second Logout() on an already-revoked session, error = %v, want nil (idempotent)", err)
	}
}

// --- cross-user rejection ---

// TestLogoutService_Logout_CrossUserRejected is requirement #2/#10: a
// user must not be able to revoke another user's session through this
// service, even if they somehow present that session's ID.
func TestLogoutService_Logout_CrossUserRejected(t *testing.T) {
	svc, sessionRepo, _ := newTestLogoutService(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})

	err := svc.Logout(t.Context(), "user-2", session.ID, LoginMeta{})
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("Logout() by a different user, error = %v, want entity.ErrNotFound", err)
	}

	stored, getErr := sessionRepo.GetByID(t.Context(), session.ID)
	if getErr != nil {
		t.Fatalf("GetByID() error = %v", getErr)
	}
	if stored.RevokedAt != nil {
		t.Error("a cross-user Logout() call actually revoked the session")
	}
}

func TestLogoutService_Logout_NonexistentSession(t *testing.T) {
	svc, _, _ := newTestLogoutService(t)
	err := svc.Logout(t.Context(), "user-1", "00000000-0000-4000-8000-000000000000", LoginMeta{})
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("Logout() for a nonexistent session, error = %v, want entity.ErrNotFound", err)
	}
}

// --- missing session identity (requirement #23) ---

func TestLogoutService_Logout_MissingSessionID(t *testing.T) {
	svc, _, audit := newTestLogoutService(t)

	err := svc.Logout(t.Context(), "user-1", "", LoginMeta{})
	if !errors.Is(err, ErrMissingSessionIdentity) {
		t.Errorf("Logout() with no session ID, error = %v, want ErrMissingSessionIdentity", err)
	}

	found := false
	for _, entry := range audit.Entries {
		if reason, _ := entry.Metadata["failure_reason"].(string); reason == "missing_session_identity" {
			found = true
		}
	}
	if !found {
		t.Error("no audit entry recorded the missing-session-identity failure")
	}
}

func TestLogoutService_Logout_MissingUserID(t *testing.T) {
	svc, _, _ := newTestLogoutService(t)
	err := svc.Logout(t.Context(), "", "some-session-id", LoginMeta{})
	if !errors.Is(err, ErrMissingSessionIdentity) {
		t.Errorf("Logout() with no user ID, error = %v, want ErrMissingSessionIdentity", err)
	}
}

// --- database failure ---

func TestLogoutService_Logout_DatabaseFailureIsSafe(t *testing.T) {
	svc, sessionRepo, _ := newTestLogoutService(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})
	dbErr := errors.New("simulated database connection error: dial tcp: connect: connection refused")
	sessionRepo.FailNextRevoke = dbErr

	err := svc.Logout(t.Context(), "user-1", session.ID, LoginMeta{})
	if !errors.Is(err, dbErr) {
		t.Errorf("Logout() error = %v, want the raw database error propagated, not a false success", err)
	}

	// The requirement this exists to enforce: a failed revoke attempt
	// must leave the session exactly as it was.
	stored, getErr := sessionRepo.GetByID(t.Context(), session.ID)
	if getErr != nil {
		t.Fatalf("GetByID() error = %v", getErr)
	}
	if stored.RevokedAt != nil {
		t.Error("session was revoked despite the forced database failure — inconsistent state")
	}
}

// --- refresh-token interaction (through session state, not a direct write) ---

// TestLogoutService_Logout_PreventsSubsequentRefresh is requirements
// #7/#8/#22 proven end to end: logging out must make a subsequent
// refresh attempt against that session fail, purely because
// RefreshTokenService.Refresh checks live session state — no refresh_tokens
// row is touched by Logout itself.
func TestLogoutService_Logout_PreventsSubsequentRefresh(t *testing.T) {
	sessionRepo := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	sessions := NewSessionService(sessionRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
	logoutSvc := NewLogoutService(LogoutServiceDeps{Sessions: sessions, AuditTx: auditTx})

	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})
	raw, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	rt := &entity.RefreshToken{
		SessionID: session.ID,
		UserID:    "user-1",
		TokenHash: util.HashToken(raw),
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := refreshTokens.Create(t.Context(), rt); err != nil {
		t.Fatalf("Create refresh token: %v", err)
	}

	keys, err := security.LoadSigningKeySet("key-1", generateTestEd25519PrivateKeyPEM(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	refreshSvc := NewRefreshTokenService(RefreshTokenServiceDeps{
		RefreshTokens:       refreshTokens,
		Sessions:            sessions,
		Tokens:              security.NewTokenService(keys, "auth-service", 10*time.Minute),
		AccessTokenAudience: "auth-service",
		AccessTokenTTL:      10 * time.Minute,
		RefreshTTL:          7 * 24 * time.Hour,
		AuditTx:             auditTx,
	})

	// Sanity: the refresh token works before logout.
	if _, err := refreshSvc.Refresh(t.Context(), raw, LoginMeta{}); err != nil {
		t.Fatalf("Refresh() before logout, error = %v, want nil", err)
	}

	// Re-seed a fresh, still-valid refresh token (the one above just
	// rotated) tied to the same session, to isolate "logout breaks
	// refresh" from "rotation breaks refresh," which 5B's own tests
	// already cover separately.
	raw2, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	rt2 := &entity.RefreshToken{
		SessionID: session.ID,
		UserID:    "user-1",
		TokenHash: util.HashToken(raw2),
		FamilyID:  "family-2",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := refreshTokens.Create(t.Context(), rt2); err != nil {
		t.Fatalf("Create second refresh token: %v", err)
	}

	if err := logoutSvc.Logout(t.Context(), "user-1", session.ID, LoginMeta{}); err != nil {
		t.Fatalf("Logout() error = %v, want nil", err)
	}

	if _, err := refreshSvc.Refresh(t.Context(), raw2, LoginMeta{}); err == nil {
		t.Error("Refresh() with a refresh token tied to a logged-out session succeeded; want an error")
	}
}

// --- audit ---

func TestLogoutService_Logout_AuditEventOnSuccess(t *testing.T) {
	svc, sessionRepo, audit := newTestLogoutService(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "hash-1", ExpiresAt: time.Now().Add(time.Hour)})

	if err := svc.Logout(t.Context(), "user-1", session.ID, LoginMeta{IPAddress: "203.0.113.42"}); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	if len(audit.Entries) != 1 {
		t.Fatalf("audit_logs has %d entries, want 1", len(audit.Entries))
	}
	entry := audit.Entries[0]
	if entry.Action != "auth.logout" {
		t.Errorf("audit action = %q, want %q", entry.Action, "auth.logout")
	}
	if entry.Result != entity.AuditResultSuccess {
		t.Errorf("audit result = %q, want %q", entry.Result, entity.AuditResultSuccess)
	}
	if entry.ActorID == nil || *entry.ActorID != "user-1" {
		t.Errorf("audit actor_id = %v, want %q", entry.ActorID, "user-1")
	}
	if entry.ResourceID == nil || *entry.ResourceID != session.ID {
		t.Errorf("audit resource_id = %v, want %q", entry.ResourceID, session.ID)
	}
}

// TestLogoutService_Logout_AuditNeverContainsCredentials enforces the
// same never-carries-a-secret requirement every other audit-writing
// service in this codebase already enforces for its own operation.
func TestLogoutService_Logout_AuditNeverContainsCredentials(t *testing.T) {
	svc, sessionRepo, audit := newTestLogoutService(t)
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: "super-secret-hash-value", ExpiresAt: time.Now().Add(time.Hour)})

	if err := svc.Logout(t.Context(), "user-1", session.ID, LoginMeta{}); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	for _, entry := range audit.Entries {
		for k, v := range entry.Metadata {
			if strings.EqualFold(k, "password") || strings.EqualFold(k, "password_hash") || strings.EqualFold(k, "token") || strings.EqualFold(k, "hash") {
				t.Errorf("audit metadata has a key named %q — must never carry a credential", k)
			}
			if s, ok := v.(string); ok && strings.Contains(s, "super-secret-hash-value") {
				t.Errorf("audit metadata[%q] = %q contains the session token hash", k, s)
			}
		}
	}
}

// --- logging hygiene ---

// TestLogoutService_Logout_NeverLogsSensitiveValues captures every log
// line across a logout call and asserts none contain the session's own
// token hash — Logout never handles a raw access or refresh token at
// all, so this mainly guards against a future edit accidentally logging
// something it shouldn't.
func TestLogoutService_Logout_NeverLogsSensitiveValues(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	ctx := logging.WithContext(t.Context(), zap.New(core))

	svc, sessionRepo, _ := newTestLogoutService(t)
	const secretHash = "super-secret-session-token-hash"
	session := sessionRepo.Seed(&entity.Session{UserID: "user-1", SessionTokenHash: secretHash, ExpiresAt: time.Now().Add(time.Hour)})

	if err := svc.Logout(ctx, "user-1", session.ID, LoginMeta{}); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	for _, entry := range logs.All() {
		line := entry.Message
		for k, v := range entry.ContextMap() {
			line += " " + k + "=" + toStringForTest(v)
		}
		if strings.Contains(line, secretHash) {
			t.Errorf("log line contains the session token hash: %q", line)
		}
	}
}
