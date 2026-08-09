package service

import (
	"errors"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
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
func newTestAuthService(t *testing.T) (*AuthService, *mocks.FakeUserRepository, *mocks.FakeRefreshTokenRepository) {
	t.Helper()
	users := mocks.NewFakeUserRepository()
	sessions := mocks.NewFakeSessionRepository()
	refreshTokens := mocks.NewFakeRefreshTokenRepository()
	loginHistory := mocks.NewFakeLoginHistoryRepository()

	svc := NewAuthService(AuthServiceDeps{
		Users:         users,
		Sessions:      sessions,
		RefreshTokens: refreshTokens,
		LoginHistory:  loginHistory,
		Tokens:        util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		Passwords:     security.NewPasswordService(testPasswordParams),
		RefreshTTL:    30 * 24 * time.Hour,
	})
	return svc, users, refreshTokens
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
	svc, users, _ := newTestAuthService(t)
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
	svc, users, _ := newTestAuthService(t)
	seedUser(t, users, "marcus.webb@acme.com", "Tr0ub4dor&3xample!")

	_, err := svc.Login(t.Context(), "org-1", "marcus.webb@acme.com", "wrong-password", LoginMeta{})
	if !errors.Is(err, entity.ErrInvalidCredentials) {
		t.Errorf("Login() error = %v, want entity.ErrInvalidCredentials", err)
	}
}

// TestLogin_LocksAfterMaxAttempts is the test that justifies
// maxFailedLoginAttempts existing as a named constant instead of a magic
// number buried in an if-statement: it pins the exact threshold.
func TestLogin_LocksAfterMaxAttempts(t *testing.T) {
	svc, users, _ := newTestAuthService(t)
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

func TestRefreshToken_RotatesAndDetectsReuse(t *testing.T) {
	svc, users, _ := newTestAuthService(t)
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
