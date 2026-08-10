//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/dto"
)

// testPassword satisfies dto.RegisterRequest.Validate's complexity rule
// (>=12 chars, upper/lower/digit/symbol) and is fixed rather than
// per-run-random: complexity doesn't depend on uniqueness, only the email
// and username identifying the account need to be unique per run.
const testPassword = "Sprint2-E2e-Test-Pw1!"

// uniqueSuffix gives each test run its own email/username so repeated runs
// (and parallel runs against the same database) never collide on the
// users.email or users.username unique constraints — a fresh Postgres row
// per run, never a hardcoded fixture user.
func uniqueSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("uniqueSuffix: %v", err)
	}
	return hex.EncodeToString(b)
}

// forbiddenResponseFields are keys that must never appear in any response
// body this suite decodes, across both success and error paths — the wire
// contract dto.RegisterResponse/dto.TokenResponse/dto.UserResponse/dto.Error
// already enforce by never declaring these fields on the Go side (see each
// type's own doc comment), but this test proves it holds for the actual
// bytes that crossed the real HTTP boundary, not just for the Go struct
// definition.
var forbiddenResponseFields = []string{"password", "password_hash", "password_algo", "private_key", "signing_key"}

func assertNoForbiddenFields(t *testing.T, context string, raw []byte, extra ...string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s: response is not valid JSON: %v", context, err)
	}
	for _, key := range append(append([]string{}, forbiddenResponseFields...), extra...) {
		if _, present := m[key]; present {
			t.Errorf("%s: response body contains forbidden field %q — sensitive data leaked to the client", context, key)
		}
	}
}

// doRequest sends req through client and returns the response together with
// its fully-drained body, so callers never need to remember to close
// resp.Body themselves. It never logs the body — callers decide what, if
// anything, is safe to include in a failure message.
func doRequest(t *testing.T, client *http.Client, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read response body: %v", req.Method, req.URL.Path, err)
	}
	return resp, raw
}

func postJSON(t *testing.T, client *http.Client, url string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doRequest(t, client, req)
}

func getWithAuth(t *testing.T, client *http.Client, url, authHeader string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return doRequest(t, client, req)
}

// TestE2E_RegistrationLoginProtectedAPI is Sprint 2 E2E Scenario #1:
// Registration -> Login -> Protected API, run entirely through the real
// http.Handler httphandler.NewRouter builds (see setup_test.go) — an actual
// HTTP client talking to an actual HTTP server, which routes through the
// actual middleware chain into the actual handlers, services, and
// PostgreSQL. Nothing in this file calls a handler or service method
// directly.
func TestE2E_RegistrationLoginProtectedAPI(t *testing.T) {
	env := newE2EEnv(t)
	client := env.Server.Client()

	suffix := uniqueSuffix(t)
	email := fmt.Sprintf("e2e-%s@example.test", suffix)
	normalizedEmail := strings.ToLower(email)
	username := "e2e-" + suffix
	orgHeaders := map[string]string{"X-Organization-Id": fixtureOrgID}

	var userID string

	// --- Scenario 1: Registration ---
	t.Run("Registration", func(t *testing.T) {
		reqBody := dto.RegisterRequest{Username: username, Email: email, Password: testPassword}
		resp, raw := postJSON(t, client, env.Server.URL+"/v1/auth/register", reqBody, orgHeaders)

		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST /v1/auth/register: status = %d, want %d; body = %s", resp.StatusCode, http.StatusCreated, raw)
		}

		var out dto.RegisterResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode RegisterResponse: %v", err)
		}
		if out.ID == "" {
			t.Fatal("RegisterResponse.ID is empty")
		}
		if out.Email != normalizedEmail {
			t.Errorf("RegisterResponse.Email = %q, want %q", out.Email, normalizedEmail)
		}
		if out.Username != username {
			t.Errorf("RegisterResponse.Username = %q, want %q", out.Username, username)
		}
		if out.Status != "active" {
			t.Errorf("RegisterResponse.Status = %q, want %q", out.Status, "active")
		}
		assertNoForbiddenFields(t, "POST /v1/auth/register response", raw, "refresh_token", "access_token")

		userID = out.ID
		t.Cleanup(func() {
			if _, err := env.DB.Exec(`DELETE FROM users WHERE id = $1`, userID); err != nil {
				t.Logf("cleanup: delete users row %s: %v", userID, err)
			}
		})

		// --- Real-PostgreSQL persistence boundary: query the database
		// directly, the same connection pool the app itself uses, never
		// through the HTTP API a second time. ---
		var dbEmail, dbUsername, dbHash, dbAlgo, dbStatus string
		row := env.DB.QueryRow(`SELECT email, username, password_hash, password_algo, status FROM users WHERE id = $1`, userID)
		if err := row.Scan(&dbEmail, &dbUsername, &dbHash, &dbAlgo, &dbStatus); err != nil {
			t.Fatalf("query persisted user %s: %v", userID, err)
		}
		if dbEmail != normalizedEmail {
			t.Errorf("persisted email = %q, want %q", dbEmail, normalizedEmail)
		}
		if dbUsername != username {
			t.Errorf("persisted username = %q, want %q", dbUsername, username)
		}
		if dbAlgo != "argon2id" {
			t.Errorf("persisted password_algo = %q, want %q", dbAlgo, "argon2id")
		}
		if dbHash == testPassword {
			t.Fatal("persisted password_hash equals the plaintext password — password was not hashed")
		}
		if !strings.HasPrefix(dbHash, "$argon2id$") {
			t.Errorf("persisted password_hash = %q, does not look like a standard Argon2id encoded hash", dbHash)
		}
		// Verify the persisted hash actually matches the plaintext password
		// using the application's own real Argon2id verification primitive
		// (the same *security.PasswordService instance AuthService.Login
		// verifies against) — proves the hash isn't merely Argon2id-shaped
		// but a hash of this password specifically.
		ok, err := env.Passwords.Verify(testPassword, dbHash)
		if err != nil {
			t.Fatalf("security.PasswordService.Verify(testPassword, persisted hash): %v", err)
		}
		if !ok {
			t.Fatal("persisted password_hash does not verify against the plaintext password that was registered")
		}
	})
	if t.Failed() {
		t.Fatal("registration did not succeed; aborting dependent scenarios")
	}

	var accessToken, sessionID string

	// --- Scenario 2: Login ---
	t.Run("Login", func(t *testing.T) {
		reqBody := dto.LoginRequest{Email: email, Password: testPassword}
		resp, raw := postJSON(t, client, env.Server.URL+"/v1/auth/login", reqBody, orgHeaders)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /v1/auth/login: status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, raw)
		}

		var out dto.TokenResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode TokenResponse: %v", err)
		}
		if out.AccessToken == "" {
			t.Fatal("TokenResponse.AccessToken is empty")
		}
		if out.RefreshToken == "" {
			t.Error("TokenResponse.RefreshToken is empty")
		}
		if out.TokenType != "Bearer" {
			t.Errorf("TokenResponse.TokenType = %q, want %q", out.TokenType, "Bearer")
		}
		if out.ExpiresIn <= 0 {
			t.Errorf("TokenResponse.ExpiresIn = %d, want a positive number of seconds", out.ExpiresIn)
		}
		if out.SessionID == "" {
			t.Error("TokenResponse.SessionID is empty")
		}
		assertNoForbiddenFields(t, "POST /v1/auth/login response", raw)

		accessToken = out.AccessToken
		sessionID = out.SessionID

		// --- Real JWT verification: decode and verify using the
		// application's own real verification mechanism
		// (*util.JWTSigner.Verify — the exact code middleware.Auth calls on
		// every protected request), never a hand-rolled or disabled check.
		// The token is never logged; only fields decoded from it are. ---
		parts := strings.Split(accessToken, ".")
		if len(parts) != 3 {
			t.Fatalf("access token is not JWT-shaped (%d dot-separated parts, want 3)", len(parts))
		}
		claims, err := env.Tokens.Verify(accessToken)
		if err != nil {
			t.Fatalf("access token failed real signature verification: %v", err)
		}
		if claims.Subject != userID {
			t.Errorf("access token sub = %q, want the registered user's ID %q", claims.Subject, userID)
		}
		if claims.OrganizationID != fixtureOrgID {
			t.Errorf("access token org_id = %q, want %q", claims.OrganizationID, fixtureOrgID)
		}
		if claims.SessionID != sessionID {
			t.Errorf("access token sid = %q, want the login response's session_id %q", claims.SessionID, sessionID)
		}
		if claims.ExpiresAt <= claims.IssuedAt {
			t.Errorf("access token exp (%d) is not after iat (%d)", claims.ExpiresAt, claims.IssuedAt)
		}
		if claims.ExpiresAtTime().Before(time.Now()) {
			t.Error("access token is already expired immediately after issuance")
		}

		// Tampering with the signature must invalidate the token — proves
		// Verify is checking the signature, not merely decoding the payload.
		tamperedSig := parts[0] + "." + parts[1] + "." + tamperLastChar(parts[2])
		if _, err := env.Tokens.Verify(tamperedSig); err == nil {
			t.Error("util.JWTSigner.Verify accepted a token with a tampered signature")
		}
	})
	if t.Failed() {
		t.Fatal("login did not succeed; aborting dependent scenarios")
	}

	// --- Scenario 3: Protected endpoint, valid token ---
	t.Run("ProtectedEndpoint_ValidToken", func(t *testing.T) {
		url := env.Server.URL + "/v1/users/" + userID
		resp, raw := getWithAuth(t, client, url, "Bearer "+accessToken)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/users/{userId} with a valid access token: status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, raw)
		}
		var out dto.UserResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode UserResponse: %v", err)
		}
		if out.ID != userID {
			t.Errorf("UserResponse.ID = %q, want %q", out.ID, userID)
		}
		if out.Email != normalizedEmail {
			t.Errorf("UserResponse.Email = %q, want %q", out.Email, normalizedEmail)
		}
		assertNoForbiddenFields(t, "GET /v1/users/{userId} response", raw)
	})

	// --- Scenario 4: Protected endpoint, no token ---
	t.Run("ProtectedEndpoint_NoToken", func(t *testing.T) {
		url := env.Server.URL + "/v1/users/" + userID
		resp, raw := getWithAuth(t, client, url, "")

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /v1/users/{userId} with no Authorization header: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		var out dto.Error
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode Error envelope: %v", err)
		}
		if out.Error.Code != dto.CodeUnauthenticated {
			t.Errorf("error code = %q, want %q", out.Error.Code, dto.CodeUnauthenticated)
		}
		assertNoForbiddenFields(t, "GET /v1/users/{userId} (no token) response", raw, "id", "email")
	})

	// --- Scenario 5: Protected endpoint, invalid token ---
	t.Run("ProtectedEndpoint_InvalidSignature", func(t *testing.T) {
		parts := strings.Split(accessToken, ".")
		if len(parts) != 3 {
			t.Fatalf("access token is not JWT-shaped (%d parts)", len(parts))
		}
		forged := parts[0] + "." + parts[1] + "." + tamperLastChar(parts[2])

		url := env.Server.URL + "/v1/users/" + userID
		resp, raw := getWithAuth(t, client, url, "Bearer "+forged)

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /v1/users/{userId} with an invalid-signature token: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		var out dto.Error
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode Error envelope: %v", err)
		}
		if out.Error.Code != dto.CodeUnauthenticated {
			t.Errorf("error code = %q, want %q", out.Error.Code, dto.CodeUnauthenticated)
		}
		assertNoForbiddenFields(t, "GET /v1/users/{userId} (invalid signature) response", raw, "id", "email")
	})

	t.Run("ProtectedEndpoint_MalformedToken", func(t *testing.T) {
		url := env.Server.URL + "/v1/users/" + userID
		resp, raw := getWithAuth(t, client, url, "Bearer not-a-jwt-at-all")

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /v1/users/{userId} with a malformed token: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		var out dto.Error
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode Error envelope: %v", err)
		}
		if out.Error.Code != dto.CodeUnauthenticated {
			t.Errorf("error code = %q, want %q", out.Error.Code, dto.CodeUnauthenticated)
		}
	})
}

// tamperLastChar flips the last character of a base64url segment to a
// different valid base64url character, guaranteeing the segment's bytes
// change without changing its length — the smallest possible signature
// forgery, and enough to prove Verify actually checks the signature rather
// than only its shape.
func tamperLastChar(s string) string {
	if s == "" {
		return s
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := s[len(s)-1]
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] != last {
			return s[:len(s)-1] + string(alphabet[i])
		}
	}
	return s
}
