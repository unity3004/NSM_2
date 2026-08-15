package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository/mocks"
)

func newTestSessionService(t *testing.T) (*SessionService, *mocks.FakeSessionRepository) {
	t.Helper()
	sessions := mocks.NewFakeSessionRepository()
	return NewSessionService(sessions), sessions
}

// --- create ---

func TestSessionService_CreateSession(t *testing.T) {
	svc, _ := newTestSessionService(t)

	created, err := svc.CreateSession(t.Context(), CreateSessionInput{
		UserID: "user-1", IPAddress: "203.0.113.42", UserAgent: "curl/8.0",
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v, want nil", err)
	}
	if created.Session.ID == "" {
		t.Error("CreateSession() returned a session with no ID")
	}
	if created.RawToken == "" {
		t.Error("CreateSession() returned no RawToken")
	}
	if !created.Session.ExpiresAt.After(time.Now()) {
		t.Errorf("ExpiresAt = %v, want it in the future", created.Session.ExpiresAt)
	}
}

// TestSessionService_CreateSession_BelongsToCorrectUser proves the created
// row is attributed to the requested user, not left blank or defaulted.
func TestSessionService_CreateSession_BelongsToCorrectUser(t *testing.T) {
	svc, sessions := newTestSessionService(t)

	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if created.Session.UserID != "user-1" {
		t.Errorf("Session.UserID = %q, want %q", created.Session.UserID, "user-1")
	}

	stored, err := sessions.GetByID(t.Context(), created.Session.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if stored.UserID != "user-1" {
		t.Errorf("stored session UserID = %q, want %q", stored.UserID, "user-1")
	}
}

// TestSessionService_CreateSession_TokenIsRandomAndUnique proves the raw
// bearer token — the actual security-sensitive value, as opposed to the
// UUID primary key — is generated with real entropy and never repeats
// across calls, per this milestone's "unpredictable, not a predictable
// value" requirement.
func TestSessionService_CreateSession_TokenIsRandomAndUnique(t *testing.T) {
	svc, _ := newTestSessionService(t)

	const attempts = 50
	seen := make(map[string]bool, attempts)
	for i := 0; i < attempts; i++ {
		created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
		if err != nil {
			t.Fatalf("CreateSession() error = %v", err)
		}
		// util.NewOpaqueToken encodes 32 random bytes as base64url without
		// padding — 43 characters. Anything shorter would mean less
		// entropy than intended; a sequential/timestamp-derived value
		// would also fail the uniqueness check below.
		if len(created.RawToken) < 32 {
			t.Fatalf("RawToken = %q, length %d, want at least 32 characters of entropy", created.RawToken, len(created.RawToken))
		}
		if seen[created.RawToken] {
			t.Fatalf("RawToken %q was generated twice across %d attempts", created.RawToken, attempts)
		}
		seen[created.RawToken] = true
		if seen[created.Session.ID] {
			t.Fatalf("Session.ID %q was generated twice across %d attempts", created.Session.ID, attempts)
		}
		seen[created.Session.ID] = true
	}
}

func TestSessionService_CreateSession_NonexistentUser(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	// Simulates exactly what postgres.translateError now produces for a
	// foreign-key violation on sessions.user_id — see
	// internal/repository/postgres/errors_test.go for the translation
	// itself; this proves SessionService propagates it faithfully rather
	// than masking or misclassifying it.
	sessions.FailNextCreate = entity.ErrNotFound

	_, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "no-such-user"})
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("CreateSession() for a nonexistent user, error = %v, want entity.ErrNotFound", err)
	}
}

func TestSessionService_CreateSession_DatabaseFailure(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	dbErr := errors.New("simulated database connection error: dial tcp: connect: connection refused")
	sessions.FailNextCreate = dbErr

	_, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if !errors.Is(err, dbErr) {
		t.Errorf("CreateSession() error = %v, want the raw database error propagated", err)
	}
	// It must not be misclassified as a domain-specific outcome it isn't.
	if errors.Is(err, entity.ErrNotFound) {
		t.Error("CreateSession() turned a database failure into entity.ErrNotFound")
	}
}

// --- retrieval ---

func TestSessionService_GetSession(t *testing.T) {
	svc, _ := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	got, err := svc.GetSession(t.Context(), "user-1", created.Session.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v, want nil", err)
	}
	if got.ID != created.Session.ID {
		t.Errorf("GetSession() returned session %q, want %q", got.ID, created.Session.ID)
	}
}

func TestSessionService_GetSession_Nonexistent(t *testing.T) {
	svc, _ := newTestSessionService(t)

	_, err := svc.GetSession(t.Context(), "user-1", "00000000-0000-4000-8000-000000000000")
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetSession() for a nonexistent session, error = %v, want entity.ErrNotFound", err)
	}
}

// TestSessionService_GetSession_CrossUserAccessRejected is the core
// authorization requirement: a session's owner is the only caller who may
// look it up, and a non-owner gets exactly the same error a nonexistent
// session would produce — never a distinguishable "yes it exists, but not
// yours" response.
func TestSessionService_GetSession_CrossUserAccessRejected(t *testing.T) {
	svc, _ := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	_, err = svc.GetSession(t.Context(), "user-2", created.Session.ID)
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetSession() by a different user, error = %v, want entity.ErrNotFound", err)
	}
}

func TestSessionService_GetSession_DatabaseFailure(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	dbErr := errors.New("simulated database connection error")
	sessions.FailNextGetByID = dbErr

	_, err := svc.GetSession(t.Context(), "user-1", "any-id")
	if !errors.Is(err, dbErr) {
		t.Errorf("GetSession() error = %v, want the raw database error propagated", err)
	}
}

// --- validation ---

func TestSessionService_ValidateSession_Active(t *testing.T) {
	svc, _ := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	got, err := svc.ValidateSession(t.Context(), created.Session.ID)
	if err != nil {
		t.Fatalf("ValidateSession() on a fresh session, error = %v, want nil", err)
	}
	if got.UserID != "user-1" {
		t.Errorf("ValidateSession() returned UserID = %q, want %q", got.UserID, "user-1")
	}
}

func TestSessionService_ValidateSession_Revoked(t *testing.T) {
	svc, _ := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := svc.RevokeSession(t.Context(), "user-1", created.Session.ID, entity.RevocationLogout); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	_, err = svc.ValidateSession(t.Context(), created.Session.ID)
	if !errors.Is(err, entity.ErrSessionRevoked) {
		t.Errorf("ValidateSession() on a revoked session, error = %v, want entity.ErrSessionRevoked", err)
	}
}

func TestSessionService_ValidateSession_Expired(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	// Force expiry without waiting an hour: reach into the fake the same
	// way a real clock eventually would.
	expired, _ := sessions.GetByID(t.Context(), created.Session.ID)
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	sessions.Seed(expired)

	_, err = svc.ValidateSession(t.Context(), created.Session.ID)
	if !errors.Is(err, entity.ErrSessionExpired) {
		t.Errorf("ValidateSession() on an expired session, error = %v, want entity.ErrSessionExpired", err)
	}

	// ExpireSession where appropriate: validating an expired session must
	// have persisted that fact, not just reported it once.
	stored, err := sessions.GetByID(t.Context(), created.Session.ID)
	if err != nil {
		t.Fatalf("GetByID() after ValidateSession(), error = %v", err)
	}
	if stored.RevokedAt == nil {
		t.Error("expired session was not persisted as revoked")
	}
	if stored.RevokedReason == nil || *stored.RevokedReason != entity.RevocationExpired {
		t.Errorf("RevokedReason = %v, want %q", stored.RevokedReason, entity.RevocationExpired)
	}
}

func TestSessionService_ValidateSession_Nonexistent(t *testing.T) {
	svc, _ := newTestSessionService(t)

	_, err := svc.ValidateSession(t.Context(), "00000000-0000-4000-8000-000000000000")
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("ValidateSession() for a nonexistent session, error = %v, want entity.ErrNotFound", err)
	}
}

// --- revocation ---

func TestSessionService_RevokeSession(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if err := svc.RevokeSession(t.Context(), "user-1", created.Session.ID, entity.RevocationLogout); err != nil {
		t.Fatalf("RevokeSession() error = %v, want nil", err)
	}

	stored, err := sessions.GetByID(t.Context(), created.Session.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if stored.RevokedAt == nil {
		t.Error("RevokeSession() did not persist revoked_at")
	}
	if stored.IsActive(time.Now()) {
		t.Error("a revoked session reports IsActive() = true")
	}
}

// TestSessionService_RevokeSession_AlreadyRevoked proves the idempotency
// requirement directly: revoking twice must succeed both times, not error
// on the second call.
func TestSessionService_RevokeSession_AlreadyRevoked(t *testing.T) {
	svc, _ := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if err := svc.RevokeSession(t.Context(), "user-1", created.Session.ID, entity.RevocationLogout); err != nil {
		t.Fatalf("first RevokeSession() error = %v, want nil", err)
	}
	if err := svc.RevokeSession(t.Context(), "user-1", created.Session.ID, entity.RevocationLogout); err != nil {
		t.Errorf("second RevokeSession() on an already-revoked session, error = %v, want nil (idempotent)", err)
	}
}

func TestSessionService_RevokeSession_Nonexistent(t *testing.T) {
	svc, _ := newTestSessionService(t)

	err := svc.RevokeSession(t.Context(), "user-1", "00000000-0000-4000-8000-000000000000", entity.RevocationLogout)
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("RevokeSession() for a nonexistent session, error = %v, want entity.ErrNotFound", err)
	}
}

// TestSessionService_RevokeSession_CrossUserAccessRejected proves a
// session cannot be revoked through another user's context — the
// requirement that matters most, since revocation is destructive.
func TestSessionService_RevokeSession_CrossUserAccessRejected(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	err = svc.RevokeSession(t.Context(), "user-2", created.Session.ID, entity.RevocationLogout)
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("RevokeSession() by a different user, error = %v, want entity.ErrNotFound", err)
	}

	stored, getErr := sessions.GetByID(t.Context(), created.Session.ID)
	if getErr != nil {
		t.Fatalf("GetByID() error = %v", getErr)
	}
	if stored.RevokedAt != nil {
		t.Error("a cross-user RevokeSession() call actually revoked the session")
	}
}

func TestSessionService_RevokeSession_DatabaseFailure(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	dbErr := errors.New("simulated database connection error")
	sessions.FailNextRevoke = dbErr

	err = svc.RevokeSession(t.Context(), "user-1", created.Session.ID, entity.RevocationLogout)
	if !errors.Is(err, dbErr) {
		t.Errorf("RevokeSession() error = %v, want the raw database error propagated", err)
	}
}

// --- expiration ---

func TestSessionService_ExpireSession_Idempotent(t *testing.T) {
	svc, sessions := newTestSessionService(t)
	created, err := svc.CreateSession(t.Context(), CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if err := svc.ExpireSession(t.Context(), created.Session.ID); err != nil {
		t.Fatalf("first ExpireSession() error = %v, want nil", err)
	}
	if err := svc.ExpireSession(t.Context(), created.Session.ID); err != nil {
		t.Errorf("second ExpireSession() error = %v, want nil (idempotent)", err)
	}
	if err := svc.ExpireSession(t.Context(), "00000000-0000-4000-8000-000000000000"); err != nil {
		t.Errorf("ExpireSession() on a nonexistent session, error = %v, want nil", err)
	}

	stored, err := sessions.GetByID(t.Context(), created.Session.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if stored.RevokedReason == nil || *stored.RevokedReason != entity.RevocationExpired {
		t.Errorf("RevokedReason = %v, want %q", stored.RevokedReason, entity.RevocationExpired)
	}
}

// --- logging hygiene ---

// TestSessionService_NeverLogsSensitiveSessionInformation captures every
// log line SessionService actually emits across a create/revoke cycle and
// asserts none of them contain the raw bearer token, its hash, or the
// full session ID — not just that this looks true from reading the
// source. observer.New gives a real zap core, not a mock of one.
func TestSessionService_NeverLogsSensitiveSessionInformation(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	ctx := logging.WithContext(t.Context(), zap.New(core))

	svc, _ := newTestSessionService(t)
	created, err := svc.CreateSession(ctx, CreateSessionInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if err := svc.RevokeSession(ctx, "user-1", created.Session.ID, entity.RevocationLogout); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	for _, entry := range logs.All() {
		line := entry.Message
		for k, v := range entry.ContextMap() {
			line += " " + k + "=" + fmt.Sprint(v)
		}
		if strings.Contains(line, created.RawToken) {
			t.Errorf("log line contains the raw session token: %q", line)
		}
		if strings.Contains(line, created.Session.SessionTokenHash) {
			t.Errorf("log line contains the session token hash: %q", line)
		}
		if strings.Contains(line, created.Session.ID) {
			t.Errorf("log line contains the full session ID (avoidable — see this milestone's report): %q", line)
		}
	}
}
