package middleware

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
)

const testAudience = "auth-service"

// generateTestEd25519PrivateKeyPEM returns a freshly generated (never
// persisted anywhere) PKCS#8 PEM-encoded Ed25519 private key — a test
// fixture only, matching internal/security's own test helper of the same
// shape.
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

func newTestTokenService(t *testing.T, keyID, issuer string, ttl time.Duration) *security.TokenService {
	t.Helper()
	keys, err := security.LoadSigningKeySet(keyID, generateTestEd25519PrivateKeyPEM(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	return security.NewTokenService(keys, issuer, ttl)
}

// identityEchoHandler is the "protected handler" every test's request
// eventually reaches (or doesn't) — it reports what Authenticate put on
// the context via response headers, so tests can assert on it without
// needing anything fancier than httptest.
func identityEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := IdentityFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Test-Subject", identity.Subject)
		w.Header().Set("X-Test-Session-Id", identity.SessionID)
		w.Header().Set("X-Test-Token-Id", identity.TokenID)
		w.WriteHeader(http.StatusOK)
	})
}

func doAuthenticatedRequest(tokens *security.TokenService, audience, authorizationHeader string) *httptest.ResponseRecorder {
	handler := Authenticate(tokens, audience)(identityEchoHandler())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if authorizationHeader != "" {
		req.Header.Set("Authorization", authorizationHeader)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// --- valid token ---

func TestAuthenticate_ValidToken(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	access, err := tokens.CreateAccessToken("user-1", testAudience, "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	rec := doAuthenticatedRequest(tokens, testAudience, "Bearer "+access)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Test-Subject"); got != "user-1" {
		t.Errorf("downstream saw Subject = %q, want %q", got, "user-1")
	}
	// The real, previously-missing piece this milestone fixed: a real
	// token, through the real middleware.Authenticate chain, must now
	// surface its session ID to downstream handlers (e.g.
	// logoutHandler.logout) rather than always reporting it empty.
	if got := rec.Header().Get("X-Test-Session-Id"); got != "session-1" {
		t.Errorf("downstream saw SessionID = %q, want %q", got, "session-1")
	}
	if rec.Header().Get("X-Test-Token-Id") == "" {
		t.Error("downstream saw an empty TokenID")
	}
}

// --- header extraction failures: all collapse to 401 ---

func TestAuthenticate_MissingAuthorizationHeader(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	rec := doAuthenticatedRequest(tokens, testAudience, "")
	assertUnauthenticated(t, rec)
}

func TestAuthenticate_EmptyAuthorizationHeader(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "")
	rec := httptest.NewRecorder()
	Authenticate(tokens, testAudience)(identityEchoHandler()).ServeHTTP(rec, req)
	assertUnauthenticated(t, rec)
}

func TestAuthenticate_MissingBearerToken(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	for _, header := range []string{"Bearer", "Bearer "} {
		rec := doAuthenticatedRequest(tokens, testAudience, header)
		assertUnauthenticated(t, rec)
	}
}

func TestAuthenticate_WrongScheme(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	rec := doAuthenticatedRequest(tokens, testAudience, "Basic dXNlcjpwYXNz")
	assertUnauthenticated(t, rec)
}

func TestAuthenticate_MalformedAuthorizationHeader(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	for _, header := range []string{"garbage-with-no-scheme-separator", "  ", "Bearer  "} {
		rec := doAuthenticatedRequest(tokens, testAudience, header)
		assertUnauthenticated(t, rec)
	}
}

// --- token validation failures: all delegated to TokenService, all collapse to 401 ---

func TestAuthenticate_InvalidJWT(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	rec := doAuthenticatedRequest(tokens, testAudience, "Bearer not-a-real-jwt")
	assertUnauthenticated(t, rec)
}

func TestAuthenticate_ExpiredJWT(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", -time.Minute)
	access, err := tokens.CreateAccessToken("user-1", testAudience, "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	rec := doAuthenticatedRequest(tokens, testAudience, "Bearer "+access)
	assertUnauthenticated(t, rec)
}

func TestAuthenticate_WrongAudience(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	access, err := tokens.CreateAccessToken("user-1", testAudience, "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	rec := doAuthenticatedRequest(tokens, "some-other-api", "Bearer "+access)
	assertUnauthenticated(t, rec)
}

func TestAuthenticate_WrongIssuer(t *testing.T) {
	issuerA := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	access, err := issuerA.CreateAccessToken("user-1", testAudience, "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	// The middleware's own TokenService is configured with a different
	// issuer than the one that actually signed this token.
	issuerB := newTestTokenService(t, "key-1", "some-other-issuer", time.Hour)
	rec := doAuthenticatedRequest(issuerB, testAudience, "Bearer "+access)
	assertUnauthenticated(t, rec)
}

func TestAuthenticate_InvalidSignature(t *testing.T) {
	signerA := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	access, err := signerA.CreateAccessToken("user-1", testAudience, "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	// Same kid label, different actual key material — the middleware's
	// signature check must fail on cryptographic grounds, not a missing
	// key lookup.
	signerB := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	rec := doAuthenticatedRequest(signerB, testAudience, "Bearer "+access)
	assertUnauthenticated(t, rec)
}

// --- refresh tokens must not work as access tokens ---

// TestAuthenticate_RefreshTokenNotAcceptedAsAccessToken presents an
// opaque, high-entropy string shaped exactly like the refresh tokens
// util.NewOpaqueToken mints for Milestone 5B — never a JWT — proving the
// boundary between the two token types holds: a refresh token is
// structurally incapable of passing JWT parsing, so it can never be
// mistaken for a valid access token here.
func TestAuthenticate_RefreshTokenNotAcceptedAsAccessToken(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	refreshShapedToken, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}

	rec := doAuthenticatedRequest(tokens, testAudience, "Bearer "+refreshShapedToken)
	assertUnauthenticated(t, rec)
}

// --- identity / context ---

// TestAuthenticate_IdentityInContextAndRetrievable covers both "the
// authenticated identity is placed in context" and "a downstream handler
// can retrieve it" together — identityEchoHandler above is exactly that
// downstream handler, and its response headers are read back here.
func TestAuthenticate_IdentityInContextAndRetrievable(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	access, err := tokens.CreateAccessToken("user-42", testAudience, "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	rec := doAuthenticatedRequest(tokens, testAudience, "Bearer "+access)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d — downstream handler did not see a usable identity", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Test-Subject"); got != "user-42" {
		t.Errorf("retrieved Subject = %q, want %q", got, "user-42")
	}
}

// TestAuthenticate_RawJWTNotStoredInContext proves AuthenticatedIdentity
// never carries the raw token string in any field — structurally, not
// just "we didn't happen to test for it." Failure messages below never
// print the raw token itself, only booleans.
func TestAuthenticate_RawJWTNotStoredInContext(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)
	access, err := tokens.CreateAccessToken("user-1", testAudience, "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	var captured AuthenticatedIdentity
	var found bool
	handler := Authenticate(tokens, testAudience)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, found = IdentityFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !found {
		t.Fatal("IdentityFromContext found nothing after successful authentication")
	}
	leaked := captured.Subject == access || captured.SessionID == access || captured.TokenID == access ||
		strings.Contains(fmt.Sprintf("%+v", captured), access)
	if leaked {
		t.Error("the raw access token was found inside the stored AuthenticatedIdentity")
	}
}

// --- no authorization performed ---

// TestAuthenticate_PerformsNoAuthorization proves the middleware treats
// every validly authenticated subject identically — there is no
// allow-list, role check, or subject-specific branch anywhere in it. Two
// arbitrary, never-before-seen subjects must both simply pass through.
func TestAuthenticate_PerformsNoAuthorization(t *testing.T) {
	tokens := newTestTokenService(t, "key-1", "auth-service", time.Hour)

	for _, subject := range []string{"user-1", "some-completely-different-service-account-id"} {
		access, err := tokens.CreateAccessToken(subject, testAudience, "session-1")
		if err != nil {
			t.Fatalf("CreateAccessToken(%q): %v", subject, err)
		}
		rec := doAuthenticatedRequest(tokens, testAudience, "Bearer "+access)
		if rec.Code != http.StatusOK {
			t.Errorf("subject %q: status = %d, want %d — a valid token for any subject must pass through unconditionally", subject, rec.Code, http.StatusOK)
		}
	}
}

func assertUnauthenticated(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (UNAUTHENTICATED)", rec.Code, http.StatusUnauthorized)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"code":"UNAUTHENTICATED"`) {
		t.Errorf("response body = %s, want it to carry code UNAUTHENTICATED", body)
	}
	// The exact rejection reason must never appear in the response.
	for _, leak := range []string{"signature", "issuer", "audience", "expired", "algorithm", "malformed"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("response body leaks the specific failure reason (%q): %s", leak, body)
		}
	}
}
