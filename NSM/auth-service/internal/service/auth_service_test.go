package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
)

// testPasswordParams trade Argon2id's real cost for test speed — the
// login/lockout/rotation behavior under test doesn't depend on how
// expensive hashing is, only on whether Hash/Verify agree with each
// other. See internal/security/password_test.go's identical fastParams
// for the same reasoning applied to the primitive itself.
var testPasswordParams = security.Params{
	Memory:      8 * 1024,
	Iterations:  1,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// newTestAuthService wires AuthService against the in-memory fakes from
// internal/repository/mocks — no database, no HTTP, just the use case
// under test. This is the concrete payoff of the dependency inversion
// internal/repository exists to provide.
//
// auditTx is a plain pass-through, not FakeRegistrationTx's
// snapshot/rollback wrapper: login's audit write isn't tied to any other
// write's atomicity (see AuthService.recordLoginAudit's doc comment), so
// the test double for it doesn't need to reproduce rollback semantics —
// only UserService.Register's audit write does.
func newTestAuthService(t *testing.T) (*AuthService, *mocks.FakeUserRepository, *mocks.FakeRefreshTokenRepository, *mocks.FakeLoginHistoryRepository, *mocks.FakeAuditLogRepository) {
	t.Helper()
	users := mocks.NewFakeUserRepository()
	sessions := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	loginHistory := mocks.NewFakeLoginHistoryRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}

	svc := NewAuthService(AuthServiceDeps{
		Users:         users,
		Sessions:      sessions,
		RefreshTokens: refreshTokens,
		LoginHistory:  loginHistory,
		Tokens:        util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		Passwords:     security.NewPasswordService(testPasswordParams),
		RefreshTTL:    30 * 24 * time.Hour,
		AuditTx:       auditTx,
		// Milestone 6C: a no-op here, deliberately, not a
		// threshold-enforcing fake — TestLogin_LocksAfterMaxAttempts below
		// drives Login to the exact same failure count (5) this milestone's
		// own approved account-dimension threshold uses, and asserting on
		// the *Postgres* lockout's behavior specifically requires the new
		// Redis-layer pre-check to never itself intervene here. Rate-limit
		// behavior gets its own dedicated tests against
		// newTestAuthServiceWithAbuseProtection below, not this shared
		// helper every other test in this file also depends on.
		AbuseProtection: ratelimit.NoopAuthAbuseProtection{},
	})
	return svc, users, refreshTokens, loginHistory, audit
}

// newTestAuthServiceWithAbuseProtection is newTestAuthService plus a real,
// threshold-enforcing ratelimit.FakeAuthAbuseProtection configured with
// this milestone's approved policy — for the tests that specifically
// exercise rate-limiting behavior, kept separate from newTestAuthService
// so every other test in this file keeps the no-op default (see that
// function's comment on why sharing one fake would silently interact with
// the existing Postgres lockout threshold).
func newTestAuthServiceWithAbuseProtection(t *testing.T) (*AuthService, *mocks.FakeUserRepository, *ratelimit.FakeAuthAbuseProtection) {
	t.Helper()
	users := mocks.NewFakeUserRepository()
	sessions := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	loginHistory := mocks.NewFakeLoginHistoryRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
	abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationLogin: {
				IP:      &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 20, BlockDuration: 15 * time.Minute},
				Account: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 5, BlockDuration: 15 * time.Minute},
				Pair:    &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 5, BlockDuration: 15 * time.Minute},
			},
		},
	})

	svc := NewAuthService(AuthServiceDeps{
		Users:               users,
		Sessions:            sessions,
		RefreshTokens:       refreshTokens,
		LoginHistory:        loginHistory,
		Tokens:              util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		Passwords:           security.NewPasswordService(testPasswordParams),
		RefreshTTL:          30 * 24 * time.Hour,
		AuditTx:             auditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: 60 * time.Second,
	})
	return svc, users, abuseProtection
}

func seedUser(t *testing.T, users *mocks.FakeUserRepository, email, password string) *entity.User {
	t.Helper()
	hash, err := security.NewPasswordService(testPasswordParams).Hash(password)
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

func TestLogin_Success(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	result, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.42"})
	if err != nil {
		t.Fatalf("Login() error = %v, want nil", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" || result.SessionID == "" {
		t.Errorf("Login() returned an incomplete result: %+v", result)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	_, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "wrong-password", LoginMeta{})
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want entity.ErrInvalidCredentials", err)
	}
}

// TestLogin_NonExistentUser is TestLogin_WrongPassword's counterpart: the
// anti-enumeration requirement means these two must be indistinguishable
// from the outside, so both are asserted to produce the exact same
// entity.ErrInvalidCredentials — never entity.ErrNotFound leaking through.
func TestLogin_NonExistentUser(t *testing.T) {
	svc, _, _, loginHistory, _ := newTestAuthService(t)

	_, err := svc.Login(t.Context(), "org-1", "nobody@acme.com", "whatever-password", LoginMeta{})
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want entity.ErrInvalidCredentials", err)
	}
	if errors.Is(err, entity.ErrNotFound) {
		t.Error("Login() error wraps entity.ErrNotFound — that would let a caller distinguish this from a wrong password")
	}

	if len(loginHistory.Entries) != 1 {
		t.Fatalf("login_history has %d entries, want 1", len(loginHistory.Entries))
	}
	if loginHistory.Entries[0].Status != entity.LoginFailureUnknownIdentity {
		t.Errorf("login_history status = %q, want %q", loginHistory.Entries[0].Status, entity.LoginFailureUnknownIdentity)
	}
}

func TestLogin_DisabledAccount(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	u := seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")
	u.Status = entity.UserStatusDisabled

	_, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{})
	if !errors.Is(err, entity.ErrAccountDisabled) {
		t.Errorf("Login() error = %v, want entity.ErrAccountDisabled", err)
	}
}

// TestLogin_AlreadyLockedAccount covers an account locked *before* this
// login attempt (e.g. by a previous request) — distinct from
// TestLogin_LocksAfterMaxAttempts below, which proves the lockout is
// applied in the first place. A correct password must not unlock it early.
func TestLogin_AlreadyLockedAccount(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	u := seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")
	until := time.Now().Add(10 * time.Minute)
	u.LockedUntil = &until

	_, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{})
	var locked AccountLockedError
	if !errors.As(err, &locked) {
		t.Errorf("Login() error = %v, want AccountLockedError", err)
	}
}

// TestLogin_LocksAfterMaxAttempts is the test that justifies
// maxFailedLoginAttempts existing as a named constant instead of a magic
// number buried in an if-statement: it pins the exact threshold.
func TestLogin_LocksAfterMaxAttempts(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	var lastErr error
	for i := 0; i < maxFailedLoginAttempts; i++ {
		_, lastErr = svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "wrong-password", LoginMeta{})
	}

	var locked AccountLockedError
	if !errors.As(lastErr, &locked) {
		t.Fatalf("after %d failed attempts, Login() error = %v, want AccountLockedError", maxFailedLoginAttempts, lastErr)
	}

	// A correct password no longer helps until the lockout window passes.
	_, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{})
	if !errors.As(err, &locked) {
		t.Errorf("Login() with correct password during lockout = %v, want AccountLockedError", err)
	}
}

// TestLogin_MalformedInput_MissingPassword proves an empty password is
// handled the same safe way as a wrong one — this exercises AuthService
// directly (dto.LoginRequest.Validate would normally reject this first;
// see internal/dto/auth_test.go and internal/handler/http/login_test.go
// for the layers that actually sit in front of this in production) so the
// service itself is proven never to panic or special-case an empty
// password into anything other than a failed verification.
func TestLogin_MalformedInput_MissingPassword(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	_, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "", LoginMeta{})
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("Login() with empty password, error = %v, want entity.ErrInvalidCredentials", err)
	}
}

// TestLogin_DatabaseFailure proves a genuine lookup failure (the database
// is unavailable) stays distinguishable *internally* — it must not be
// silently turned into entity.ErrInvalidCredentials — while
// writeServiceError's default branch is what keeps the external response
// equally generic either way (see internal/handler/http/response.go).
func TestLogin_DatabaseFailure(t *testing.T) {
	svc, users, _, loginHistory, _ := newTestAuthService(t)
	dbErr := errors.New("simulated database connection error: dial tcp: connect: connection refused")
	users.FailNextGetByEmail = dbErr

	_, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{})
	if !errors.Is(err, dbErr) {
		t.Errorf("Login() error = %v, want the raw database error propagated, not collapsed into ErrInvalidCredentials", err)
	}
	if errors.Is(err, entity.ErrInvalidCredentials) {
		t.Error("Login() turned a database failure into entity.ErrInvalidCredentials")
	}

	if len(loginHistory.Entries) != 1 {
		t.Fatalf("login_history has %d entries, want 1", len(loginHistory.Entries))
	}
	if loginHistory.Entries[0].Status != entity.LoginFailureOther {
		t.Errorf("login_history status = %q, want %q", loginHistory.Entries[0].Status, entity.LoginFailureOther)
	}
}

// TestLogin_NormalizesEmailBeforeLookup proves a login for a differently
// cased/whitespace-padded address finds the same row Register's own
// normalization stored — see UserService.Register / util.NormalizeEmail.
func TestLogin_NormalizesEmailBeforeLookup(t *testing.T) {
	svc, users, _, loginHistory, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	_, err := svc.Login(t.Context(), "org-1", "  Marcus.Webb@ACME.com  ", "Tr0ub4dor&3xample!", LoginMeta{})
	if err != nil {
		t.Fatalf("Login() with a differently-cased email, error = %v, want nil", err)
	}

	if len(loginHistory.Entries) != 1 {
		t.Fatalf("login_history has %d entries, want 1", len(loginHistory.Entries))
	}
	if loginHistory.Entries[0].AttemptedIdentifier == nil || *loginHistory.Entries[0].AttemptedIdentifier != "marcus.webb@acme.com" {
		t.Errorf("login_history attempted_identifier = %v, want the normalized address", loginHistory.Entries[0].AttemptedIdentifier)
	}
}

func TestLogin_RecordsLoginHistoryOnSuccess(t *testing.T) {
	svc, users, _, loginHistory, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	result, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{IPAddress: "203.0.113.42"})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if len(loginHistory.Entries) != 1 {
		t.Fatalf("login_history has %d entries, want 1", len(loginHistory.Entries))
	}
	entry := loginHistory.Entries[0]
	if entry.Status != entity.LoginSuccess {
		t.Errorf("login_history status = %q, want %q", entry.Status, entity.LoginSuccess)
	}
	if entry.SessionID == nil || *entry.SessionID != result.SessionID {
		t.Errorf("login_history session_id = %v, want %q", entry.SessionID, result.SessionID)
	}
	if entry.IPAddress == nil || *entry.IPAddress != "203.0.113.42" {
		t.Errorf("login_history ip_address = %v, want %q", entry.IPAddress, "203.0.113.42")
	}
}

func TestLogin_RecordsLoginHistoryOnFailure(t *testing.T) {
	svc, users, _, loginHistory, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	if _, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "wrong-password", LoginMeta{}); err == nil {
		t.Fatal("Login() with a wrong password = nil error, want one")
	}

	if len(loginHistory.Entries) != 1 {
		t.Fatalf("login_history has %d entries, want 1", len(loginHistory.Entries))
	}
	if loginHistory.Entries[0].Status != entity.LoginFailureBadPassword {
		t.Errorf("login_history status = %q, want %q", loginHistory.Entries[0].Status, entity.LoginFailureBadPassword)
	}
}

func TestLogin_RecordsAuditEventOnSuccess(t *testing.T) {
	svc, users, _, _, audit := newTestAuthService(t)
	u := seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	if _, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{}); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if len(audit.Entries) != 1 {
		t.Fatalf("audit_logs has %d entries, want 1", len(audit.Entries))
	}
	entry := audit.Entries[0]
	if entry.Action != "user.login" {
		t.Errorf("audit action = %q, want %q", entry.Action, "user.login")
	}
	if entry.Result != entity.AuditResultSuccess {
		t.Errorf("audit result = %q, want %q", entry.Result, entity.AuditResultSuccess)
	}
	if entry.ActorID == nil || *entry.ActorID != u.ID {
		t.Errorf("audit actor_id = %v, want %q", entry.ActorID, u.ID)
	}
}

// TestLogin_RecordsAuditEventOnFailure also enforces the same
// never-carries-a-secret requirement TestRegister_AuditEventCreated
// enforces for registration (see internal/service/user_service_test.go):
// the audit record's own metadata must never contain the plaintext
// password, no matter how the failure happened.
func TestLogin_RecordsAuditEventOnFailure(t *testing.T) {
	svc, users, _, _, audit := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")
	const wrongPassword = "wrong-password-example"

	if _, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", wrongPassword, LoginMeta{}); err == nil {
		t.Fatal("Login() with a wrong password = nil error, want one")
	}

	if len(audit.Entries) != 1 {
		t.Fatalf("audit_logs has %d entries, want 1", len(audit.Entries))
	}
	entry := audit.Entries[0]
	if entry.Result != entity.AuditResultFailure {
		t.Errorf("audit result = %q, want %q", entry.Result, entity.AuditResultFailure)
	}
	for k, v := range entry.Metadata {
		if strings.EqualFold(k, "password") || strings.EqualFold(k, "password_hash") || strings.EqualFold(k, "hash") {
			t.Errorf("audit metadata has a key named %q — must never carry a password or hash", k)
		}
		if s, ok := v.(string); ok && strings.Contains(s, wrongPassword) {
			t.Errorf("audit metadata[%q] = %q contains the plaintext password", k, s)
		}
	}
}

func TestRefreshToken_RotatesAndDetectsReuse(t *testing.T) {
	svc, users, _, _, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	first, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "Tr0ub4dor&3xample!", LoginMeta{})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	second, err := svc.RefreshToken(t.Context(), first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken() first rotation error = %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("RefreshToken() returned the same token instead of rotating it")
	}

	// Reusing the now-superseded first token is the theft signature.
	if _, err := svc.RefreshToken(t.Context(), first.RefreshToken); !errors.Is(err, entity.ErrTokenReuseDetected) {
		t.Errorf("RefreshToken() on a reused token = %v, want entity.ErrTokenReuseDetected", err)
	}

	// The reuse should have revoked the whole family, including the
	// legitimate second token.
	if _, err := svc.RefreshToken(t.Context(), second.RefreshToken); err == nil {
		t.Error("RefreshToken() on the second token succeeded after family revocation; want an error")
	}
}
