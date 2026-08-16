package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
)

const testRefreshAudience = "auth-service"

// newTestRefreshTokenService defaults AbuseProtection to a no-op — see
// newTestAuthService's identical choice in auth_service_test.go for why: a
// threshold-enforcing fake shared across every test in this file risks
// silently interacting with concurrency/reuse-detection tests that call
// Refresh many times in a row. Rate-limit-specific behavior gets its own
// dedicated helper, newTestRefreshTokenServiceWithAbuseProtection, below.
func newTestRefreshTokenService(t *testing.T) (*RefreshTokenService, *mocks.FakeRefreshTokenRepository, *mocks.FakeSessionRepository, *mocks.FakeAuditLogRepository) {
	t.Helper()
	svc, refreshTokens, sessionRepo, audit, _ := newRefreshTokenServiceDeps(t, ratelimit.NoopAuthAbuseProtection{})
	return svc, refreshTokens, sessionRepo, audit
}

// newTestRefreshTokenServiceWithAbuseProtection wires a real,
// threshold-enforcing ratelimit.FakeAuthAbuseProtection configured with
// this milestone's approved refresh policy (IP-only, limit 30) — for
// tests that specifically exercise rate-limiting behavior.
func newTestRefreshTokenServiceWithAbuseProtection(t *testing.T) (*RefreshTokenService, *mocks.FakeRefreshTokenRepository, *mocks.FakeSessionRepository, *ratelimit.FakeAuthAbuseProtection) {
	t.Helper()
	abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationRefresh: {
				IP: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 30, BlockDuration: 15 * time.Minute},
			},
		},
	})
	svc, refreshTokens, sessionRepo, _, _ := newRefreshTokenServiceDeps(t, abuseProtection)
	return svc, refreshTokens, sessionRepo, abuseProtection
}

func newRefreshTokenServiceDeps(t *testing.T, abuseProtection ratelimit.AuthAbuseProtection) (*RefreshTokenService, *mocks.FakeRefreshTokenRepository, *mocks.FakeSessionRepository, *mocks.FakeAuditLogRepository, *security.TokenService) {
	t.Helper()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	sessionRepo := mocks.NewFakeSessionRepository()
	sessions := NewSessionService(sessionRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}

	keys, err := security.LoadSigningKeySet("test-key-1", generateTestEd25519PrivateKeyPEM(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	tokens := security.NewTokenService(keys, "auth-service", 10*time.Minute)

	svc := NewRefreshTokenService(RefreshTokenServiceDeps{
		RefreshTokens:       refreshTokens,
		Sessions:            sessions,
		Tokens:              tokens,
		AccessTokenAudience: testRefreshAudience,
		AccessTokenTTL:      10 * time.Minute,
		RefreshTTL:          7 * 24 * time.Hour,
		AuditTx:             auditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: 60 * time.Second,
	})
	return svc, refreshTokens, sessionRepo, audit, tokens
}

// seedRefreshToken creates a session and a refresh token belonging to it,
// returning the raw (pre-hash) token Refresh expects a caller to present.
// sessionExpiresAt/tokenExpiresAt/revoked let individual tests arrange the
// exact state they need to test against.
func seedRefreshToken(t *testing.T, sessionRepo *mocks.FakeSessionRepository, refreshTokens *mocks.FakeRefreshTokenRepository, userID string, sessionExpiresAt, tokenExpiresAt time.Time) (raw string, rt *entity.RefreshToken) {
	t.Helper()
	session := sessionRepo.Seed(&entity.Session{
		UserID:           userID,
		SessionTokenHash: util.NewUUID(),
		ExpiresAt:        sessionExpiresAt,
	})

	raw, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	rt = &entity.RefreshToken{
		SessionID: session.ID,
		UserID:    userID,
		TokenHash: util.HashToken(raw),
		FamilyID:  util.NewUUID(),
		ExpiresAt: tokenExpiresAt,
	}
	if err := refreshTokens.Create(t.Context(), rt); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return raw, rt
}

// generateTestEd25519PrivateKeyPEM returns a freshly generated (never
// persisted anywhere) PKCS#8 PEM-encoded Ed25519 private key — a test
// fixture only, matching internal/security's own test helper of the same
// shape (kept package-local rather than shared, since it's ten lines and
// test helpers aren't typically exported across package boundaries for
// something this small).
func generateTestEd25519PrivateKeyPEM(t *testing.T) string {
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

// --- successful refresh ---

func TestRefreshTokenService_Refresh_Success(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	result, err := svc.Refresh(t.Context(), raw, LoginMeta{IPAddress: "203.0.113.42"})
	if err != nil {
		t.Fatalf("Refresh() error = %v, want nil", err)
	}
	if result.AccessToken == "" {
		t.Error("Refresh() returned no access token")
	}
	if result.RefreshToken == "" || result.RefreshToken == raw {
		t.Error("Refresh() returned no new refresh token, or returned the same one")
	}
	if result.ExpiresIn <= 0 {
		t.Errorf("ExpiresIn = %d, want a positive number of seconds", result.ExpiresIn)
	}
	if result.SessionID == "" {
		t.Error("Refresh() returned no session ID")
	}
}

// --- randomness / entropy / storage ---

// TestRefreshTokenService_Refresh_TokenIsRandomAndUnique covers "randomly
// generated" and "sufficient entropy" together: util.NewOpaqueToken's
// output is 32 raw bytes, base64url-encoded (43 chars, no padding); this
// asserts that length directly rather than assuming it, and proves
// uniqueness across many rotations.
func TestRefreshTokenService_Refresh_TokenIsRandomAndUnique(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour))

	const attempts = 25
	seen := map[string]bool{raw: true}
	for i := 0; i < attempts; i++ {
		result, err := svc.Refresh(t.Context(), raw, LoginMeta{})
		if err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
		if len(result.RefreshToken) < 32 {
			t.Fatalf("RefreshToken = %q, length %d, want at least 32 characters of entropy", result.RefreshToken, len(result.RefreshToken))
		}
		if seen[result.RefreshToken] {
			t.Fatalf("RefreshToken %q was generated twice across %d rotations", result.RefreshToken, attempts)
		}
		seen[result.RefreshToken] = true
		raw = result.RefreshToken
	}
}

// TestRefreshTokenService_Refresh_OnlyHashIsStored proves the stored
// entity never carries the plaintext token — checked directly against
// the fake's stored rows, the same way TestRegister_PasswordStoredOnlyAsArgon2idHash
// checks Argon2id storage.
func TestRefreshTokenService_Refresh_OnlyHashIsStored(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, original := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	if _, err := svc.Refresh(t.Context(), raw, LoginMeta{}); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	stored, err := refreshTokens.GetByTokenHash(t.Context(), original.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error = %v", err)
	}
	if stored.TokenHash == raw {
		t.Error("stored TokenHash equals the plaintext raw token")
	}
	if strings.Contains(stored.TokenHash, raw) {
		t.Error("stored TokenHash contains the plaintext raw token")
	}
}

// --- rejections ---

func TestRefreshTokenService_Refresh_IncorrectToken(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	_, err := svc.Refresh(t.Context(), "this-token-was-never-issued", LoginMeta{})
	if !errors.Is(err, entity.ErrTokenExpired) {
		t.Errorf("Refresh() with an unknown token, error = %v, want entity.ErrTokenExpired", err)
	}
}

func TestRefreshTokenService_Refresh_ExpiredToken(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(-time.Minute))

	_, err := svc.Refresh(t.Context(), raw, LoginMeta{})
	if !errors.Is(err, entity.ErrTokenExpired) {
		t.Errorf("Refresh() with an expired token, error = %v, want entity.ErrTokenExpired", err)
	}
}

func TestRefreshTokenService_Refresh_RevokedToken(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, rt := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	if err := refreshTokens.RevokeFamily(t.Context(), rt.FamilyID, entity.RevocationAdminRevoked); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	_, err := svc.Refresh(t.Context(), raw, LoginMeta{})
	if !errors.Is(err, entity.ErrTokenExpired) {
		t.Errorf("Refresh() with a revoked token, error = %v, want entity.ErrTokenExpired", err)
	}
}

func TestRefreshTokenService_Refresh_RevokedSession(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, rt := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	if err := sessionRepo.Revoke(t.Context(), rt.SessionID, entity.RevocationLogout); err != nil {
		t.Fatalf("Revoke session: %v", err)
	}

	_, err := svc.Refresh(t.Context(), raw, LoginMeta{})
	if !errors.Is(err, entity.ErrTokenExpired) {
		t.Errorf("Refresh() with a revoked session, error = %v, want entity.ErrTokenExpired", err)
	}
}

func TestRefreshTokenService_Refresh_ExpiredSession(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	// The refresh token itself is still comfortably valid; only its
	// session has expired — requirement #18's "session takes precedence."
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	_, err := svc.Refresh(t.Context(), raw, LoginMeta{})
	if !errors.Is(err, entity.ErrTokenExpired) {
		t.Errorf("Refresh() with an expired session, error = %v, want entity.ErrTokenExpired", err)
	}
}

// --- rotation ---

func TestRefreshTokenService_Refresh_RotationInvalidatesOldToken(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	result, err := svc.Refresh(t.Context(), raw, LoginMeta{})
	if err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}

	// The new token must work...
	second, err := svc.Refresh(t.Context(), result.RefreshToken, LoginMeta{})
	if err != nil {
		t.Fatalf("Refresh() with the newly rotated token, error = %v, want nil", err)
	}
	if second.RefreshToken == result.RefreshToken {
		t.Error("second rotation returned the same refresh token")
	}
}

// TestRefreshTokenService_Refresh_ReuseTriggersCompromiseResponse is
// requirements #13/#15/#16 together: presenting an already-rotated token
// must be rejected, must revoke the whole family (so RT1's *legitimate*
// descendant RT2 also stops working), and must revoke the session.
func TestRefreshTokenService_Refresh_ReuseTriggersCompromiseResponse(t *testing.T) {
	svc, refreshTokens, sessionRepo, audit := newTestRefreshTokenService(t)
	rt1Raw, rt1 := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	rt2, err := svc.Refresh(t.Context(), rt1Raw, LoginMeta{})
	if err != nil {
		t.Fatalf("Refresh() (RT1->RT2) error = %v", err)
	}

	// Presenting RT1 again — the reuse.
	_, err = svc.Refresh(t.Context(), rt1Raw, LoginMeta{})
	if !errors.Is(err, entity.ErrTokenReuseDetected) {
		t.Fatalf("Refresh() reusing RT1, error = %v, want entity.ErrTokenReuseDetected", err)
	}

	// RT2 — otherwise still perfectly valid — must now be dead too: the
	// whole family was revoked, not just RT1.
	if _, err := svc.Refresh(t.Context(), rt2.RefreshToken, LoginMeta{}); err == nil {
		t.Error("Refresh() with RT2 succeeded after family-wide revocation; want an error")
	}

	// The session must be revoked too.
	session, err := sessionRepo.GetByID(t.Context(), rt1.SessionID)
	if err != nil {
		t.Fatalf("GetByID(session) error = %v", err)
	}
	if session.RevokedAt == nil {
		t.Error("session was not revoked after refresh-token reuse was detected")
	}

	// The compromise response must be audited, without ever naming the
	// token itself.
	found := false
	for _, entry := range audit.Entries {
		if entry.Result != entity.AuditResultFailure {
			continue
		}
		if reason, _ := entry.Metadata["failure_reason"].(string); reason == "reuse_detected" {
			found = true
		}
	}
	if !found {
		t.Error("no audit entry recorded the reuse-detected failure")
	}
}

// TestRefreshTokenService_Refresh_FamilyPreservedAcrossRotations is
// requirement #16: RT1 -> RT2 -> RT3 must all share one family_id, with
// parent_token_id forming the chain.
func TestRefreshTokenService_Refresh_FamilyPreservedAcrossRotations(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	rt1Raw, rt1 := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	rt2Result, err := svc.Refresh(t.Context(), rt1Raw, LoginMeta{})
	if err != nil {
		t.Fatalf("Refresh() (RT1->RT2) error = %v", err)
	}
	rt2, err := refreshTokens.GetByTokenHash(t.Context(), util.HashToken(rt2Result.RefreshToken))
	if err != nil {
		t.Fatalf("GetByTokenHash(RT2) error = %v", err)
	}
	if rt2.FamilyID != rt1.FamilyID {
		t.Errorf("RT2.FamilyID = %q, want %q (RT1's)", rt2.FamilyID, rt1.FamilyID)
	}
	if rt2.ParentTokenID == nil || *rt2.ParentTokenID != rt1.ID {
		t.Errorf("RT2.ParentTokenID = %v, want %q (RT1's ID)", rt2.ParentTokenID, rt1.ID)
	}

	rt3Result, err := svc.Refresh(t.Context(), rt2Result.RefreshToken, LoginMeta{})
	if err != nil {
		t.Fatalf("Refresh() (RT2->RT3) error = %v", err)
	}
	rt3, err := refreshTokens.GetByTokenHash(t.Context(), util.HashToken(rt3Result.RefreshToken))
	if err != nil {
		t.Fatalf("GetByTokenHash(RT3) error = %v", err)
	}
	if rt3.FamilyID != rt1.FamilyID {
		t.Errorf("RT3.FamilyID = %q, want %q (RT1's) — family must survive multiple rotations", rt3.FamilyID, rt1.FamilyID)
	}
	if rt3.ParentTokenID == nil || *rt3.ParentTokenID != rt2.ID {
		t.Errorf("RT3.ParentTokenID = %v, want %q (RT2's ID)", rt3.ParentTokenID, rt2.ID)
	}
}

// --- concurrency ---

// TestRefreshTokenService_Refresh_ConcurrentRequestsOnlyOneSucceeds is
// requirements #14/#15/#17: N goroutines racing to consume the exact same
// refresh token must result in exactly one success. FakeRefreshTokenRepository.Rotate
// serializes via its own mutex and mirrors Postgres's
// "WHERE revoked_at IS NULL" semantics (see that method's doc comment),
// so this proves RefreshTokenService's own handling of a losing race —
// not Postgres's row locking itself, which
// test/integration/refresh_token_test.go proves separately against a
// real database.
func TestRefreshTokenService_Refresh_ConcurrentRequestsOnlyOneSucceeds(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	const concurrency = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	var successResult *RefreshResult

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := svc.Refresh(context.Background(), raw, LoginMeta{})
			if err == nil {
				mu.Lock()
				successes++
				successResult = result
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("successes = %d, want exactly 1 (concurrent refreshes of the same token)", successes)
	}
	if successResult == nil {
		t.Fatal("no goroutine succeeded at all")
	}
	// Exactly one new token must exist for this family — not one per
	// goroutine that raced past the initial GetByTokenHash check.
	if _, err := refreshTokens.GetByTokenHash(context.Background(), util.HashToken(successResult.RefreshToken)); err != nil {
		t.Errorf("the single successful rotation's new token was not found: %v", err)
	}
}

// --- database failure handling ---

// TestRefreshTokenService_Refresh_RotationFailureLeavesConsistentState is
// requirement #18: if Rotate itself fails, nothing must have changed —
// the old token must still be exactly as valid as before the attempt.
func TestRefreshTokenService_Refresh_RotationFailureLeavesConsistentState(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	raw, original := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	refreshTokens.FailNextRotate = errors.New("simulated transaction failure")

	if _, err := svc.Refresh(t.Context(), raw, LoginMeta{}); err == nil {
		t.Fatal("Refresh() with a forced rotation failure = nil error, want one")
	}

	stored, err := refreshTokens.GetByTokenHash(t.Context(), original.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error = %v", err)
	}
	if stored.RevokedAt != nil {
		t.Error("the original token was revoked despite Rotate failing — inconsistent state")
	}

	// And the token is still perfectly usable — the failure was
	// transient, not a lasting side effect.
	if _, err := svc.Refresh(t.Context(), raw, LoginMeta{}); err != nil {
		t.Errorf("Refresh() retried after a rolled-back failure, error = %v, want nil", err)
	}
}

func TestRefreshTokenService_Refresh_DatabaseFailureIsSafe(t *testing.T) {
	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	dbErr := errors.New("simulated database connection error: dial tcp: connect: connection refused")
	refreshTokens.FailNextGetByTokenHash = dbErr

	_, err := svc.Refresh(t.Context(), "anything", LoginMeta{})
	if !errors.Is(err, dbErr) {
		t.Errorf("Refresh() error = %v, want the raw database error propagated, not collapsed", err)
	}
}

// --- logging / audit hygiene ---

// TestRefreshTokenService_Refresh_NeverLogsSensitiveValues captures every
// log line across a full rotate-then-reuse cycle and checks none of them
// contain either raw token, either token's hash, or the family ID (which,
// while not a bearer secret, is still an internal identifier this
// milestone's "never log complete refresh tokens" spirit extends to
// treating cautiously) — the same zaptest/observer proof
// TestSessionService_NeverLogsSensitiveSessionInformation already used
// for Milestone 4B.
func TestRefreshTokenService_Refresh_NeverLogsSensitiveValues(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	ctx := logging.WithContext(t.Context(), zap.New(core))

	svc, refreshTokens, sessionRepo, _ := newTestRefreshTokenService(t)
	rt1Raw, _ := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	result, err := svc.Refresh(ctx, rt1Raw, LoginMeta{})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	// Trigger the reuse-detected path too, so its Warn log is covered.
	_, _ = svc.Refresh(ctx, rt1Raw, LoginMeta{})

	for _, entry := range logs.All() {
		line := entry.Message
		for k, v := range entry.ContextMap() {
			line += " " + k + "=" + toStringForTest(v)
		}
		if strings.Contains(line, rt1Raw) {
			t.Errorf("log line contains the original raw refresh token: %q", line)
		}
		if strings.Contains(line, result.RefreshToken) {
			t.Errorf("log line contains the newly rotated raw refresh token: %q", line)
		}
		if strings.Contains(line, util.HashToken(rt1Raw)) {
			t.Errorf("log line contains a refresh token hash: %q", line)
		}
	}
}

// TestRefreshTokenService_Refresh_AuditNeverContainsToken enforces the
// same never-carries-a-secret requirement TestRegister_AuditEventCreated
// and TestLogin_RecordsAuditEventOnFailure already enforce for their own
// operations.
func TestRefreshTokenService_Refresh_AuditNeverContainsToken(t *testing.T) {
	svc, refreshTokens, sessionRepo, audit := newTestRefreshTokenService(t)
	raw, original := seedRefreshToken(t, sessionRepo, refreshTokens, "user-1", time.Now().Add(time.Hour), time.Now().Add(time.Hour))

	result, err := svc.Refresh(t.Context(), raw, LoginMeta{})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	if len(audit.Entries) == 0 {
		t.Fatal("no audit entry was recorded for a successful refresh")
	}
	for _, entry := range audit.Entries {
		for k, v := range entry.Metadata {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if strings.Contains(s, raw) || strings.Contains(s, result.RefreshToken) || strings.Contains(s, original.TokenHash) {
				t.Errorf("audit metadata[%q] = %q contains a refresh token or its hash", k, s)
			}
		}
		if entry.ResourceID != nil && (*entry.ResourceID == raw || *entry.ResourceID == result.RefreshToken) {
			t.Error("audit resource_id is a raw refresh token")
		}
	}
}

func toStringForTest(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
