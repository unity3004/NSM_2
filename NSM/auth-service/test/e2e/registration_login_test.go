//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/util"
)

// e2eTestPassword satisfies dto.RegisterRequest.Validate's complexity rule
// (>=12 chars, upper, lower, digit, symbol) — an obviously fake constant,
// never written to a t.Log/t.Error message verbatim below (only compared,
// or asserted absent from a response body).
const e2eTestPassword = "E2eTestPassw0rd!"

// uniqueTestIdentity returns an email/username pair that cannot collide
// with another run or another test in this suite — never a shared,
// hardcoded test user, and never a real email domain.
func uniqueTestIdentity(t *testing.T) (email, username string) {
	t.Helper()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	return "e2e-" + suffix + "@example.test", "e2e" + suffix
}

// doJSON sends a real HTTP request to the running e2e server and decodes
// its JSON response — the only way any test in this file talks to the
// service; nothing here ever imports internal/handler/http or
// internal/service to call a handler or service method directly.
func doJSON(t *testing.T, method, url string, body any, bearer string) (status int, decoded map[string]any, raw []byte) {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Organization-Id", e2eOrgID)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded) // best-effort — a 204 has no body to decode
	}
	return resp.StatusCode, decoded, raw
}

// TestE2E_RegistrationLoginProtectedAPI is Sprint 2 E2E scenario #1: a
// client registers, logs in, and uses the resulting access token against
// a real protected endpoint — entirely over real HTTP, through the real
// router built by httphandler.NewRouter, against a real Postgres. No
// handler or service method is called directly; see newE2EServer's own
// doc comment for exactly what is and isn't real in this test.
func TestE2E_RegistrationLoginProtectedAPI(t *testing.T) {
	env := newE2EServer(t)
	email, username := uniqueTestIdentity(t)

	var accessToken string

	// --- Scenario 1: registration ---
	t.Run("registration", func(t *testing.T) {
		status, decoded, raw := doJSON(t, http.MethodPost, env.BaseURL+"/v1/auth/register", dto.RegisterRequest{
			Username: username,
			Email:    email,
			Password: e2eTestPassword,
		}, "")

		if status != http.StatusCreated {
			t.Fatalf("POST /v1/auth/register status = %d, want %d; body = %s", status, http.StatusCreated, raw)
		}
		if decoded["email"] != email {
			t.Errorf("response email = %v, want %q", decoded["email"], email)
		}
		if decoded["username"] != username {
			t.Errorf("response username = %v, want %q", decoded["username"], username)
		}
		if id, _ := decoded["id"].(string); id == "" {
			t.Error("response did not include a non-empty id")
		}

		// Security assertions: the response must never carry the
		// password, its hash, or any key material — RegisterResponse has
		// no such field at all (see dto.RegisterResponse's own doc
		// comment), checked here on the actual wire body, not just the Go
		// type definition.
		for _, forbidden := range []string{"password", "password_hash", "private_key", "refresh_token", "access_token"} {
			if _, present := decoded[forbidden]; present {
				t.Errorf("registration response unexpectedly includes field %q", forbidden)
			}
		}
		if strings.Contains(string(raw), e2eTestPassword) {
			t.Error("registration response body unexpectedly contains the plaintext password")
		}

		// Real persistence boundary: query Postgres directly — not
		// through the service or handler — for the row the HTTP call
		// claims to have created.
		stored, err := postgres.NewUserRepository(env.DB).GetByEmail(t.Context(), e2eOrgID, email)
		if err != nil {
			t.Fatalf("GetByEmail(%s): %v", email, err)
		}
		if stored.Username == nil || *stored.Username != username {
			t.Errorf("stored username = %v, want %q", stored.Username, username)
		}
		if stored.PasswordHash == nil || *stored.PasswordHash == "" {
			t.Fatal("stored user has no password hash")
		}
		if *stored.PasswordHash == e2eTestPassword {
			t.Error("stored password hash equals the plaintext password — the password was not hashed")
		}
		if !strings.HasPrefix(*stored.PasswordHash, "$argon2id$") {
			t.Errorf("stored password hash does not start with $argon2id$ (got a %d-byte value)", len(*stored.PasswordHash))
		}
	})

	// --- Scenario 2: login ---
	t.Run("login", func(t *testing.T) {
		status, decoded, raw := doJSON(t, http.MethodPost, env.BaseURL+"/v1/auth/login", dto.LoginRequest{
			Email:    email,
			Password: e2eTestPassword,
		}, "")

		if status != http.StatusOK {
			t.Fatalf("POST /v1/auth/login status = %d, want %d; body = %s", status, http.StatusOK, raw)
		}
		at, _ := decoded["access_token"].(string)
		rt, _ := decoded["refresh_token"].(string)
		if at == "" {
			t.Fatal("login response has no access_token")
		}
		if rt == "" {
			t.Error("login response has no refresh_token")
		}
		if decoded["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want %q", decoded["token_type"], "Bearer")
		}
		if sid, _ := decoded["session_id"].(string); sid == "" {
			t.Error("login response has no session_id")
		}

		for _, forbidden := range []string{"password", "password_hash", "private_key"} {
			if _, present := decoded[forbidden]; present {
				t.Errorf("login response unexpectedly includes field %q", forbidden)
			}
		}
		if strings.Contains(string(raw), e2eTestPassword) {
			t.Error("login response body unexpectedly contains the plaintext password")
		}
		if strings.Contains(string(raw), "PRIVATE KEY") {
			t.Error("login response body unexpectedly contains key material")
		}

		// Real JWT verification — the same *util.JWTSigner the router
		// itself holds (see newE2EServer), never a hand-decoded payload
		// with signature checking skipped.
		claims, err := env.TokenAuth.Verify(at)
		if err != nil {
			t.Fatalf("Verify(access_token): %v — a token minted by the real login flow must validate through the real verifier", err)
		}
		if claims.Subject == "" {
			t.Error("claims.Subject is empty")
		}
		if claims.OrganizationID != e2eOrgID {
			t.Errorf("claims.OrganizationID = %q, want %q", claims.OrganizationID, e2eOrgID)
		}
		if claims.SessionID == "" {
			t.Error("claims.SessionID is empty")
		}
		if claims.ExpiresAt <= claims.IssuedAt {
			t.Errorf("claims.ExpiresAt (%d) is not after claims.IssuedAt (%d)", claims.ExpiresAt, claims.IssuedAt)
		}
		// This is util.Claims — the pre-Milestone-6A HS256 format
		// AuthService.issueSession still mints (see that method's own
		// doc comment) — which carries no iss/aud claim at all; that
		// belongs to security.AccessTokenClaims, the newer Ed25519 format
		// minted only by POST /v1/auth/refresh. Asserting an iss/aud here
		// would be asserting a claim this token format was never designed
		// to carry, not a gap in this test.

		accessToken = at
	})

	// --- Scenario 3: protected endpoint, valid token ---
	t.Run("protected endpoint accepts the login token", func(t *testing.T) {
		if accessToken == "" {
			t.Fatal("no access token from the login subtest")
		}
		status, decoded, raw := doJSON(t, http.MethodGet, env.BaseURL+"/v1/users", nil, accessToken)
		if status != http.StatusOK {
			t.Fatalf("GET /v1/users with a valid token, status = %d, want %d; body = %s", status, http.StatusOK, raw)
		}
		data, ok := decoded["data"].([]any)
		if !ok {
			t.Fatalf("response has no data array: %s", raw)
		}
		found := false
		for _, item := range data {
			if user, ok := item.(map[string]any); ok && user["email"] == email {
				found = true
			}
		}
		if !found {
			t.Error("the registered user does not appear in GET /v1/users' response — the authenticated request did not reach real data")
		}
	})

	// --- Scenario 4: protected endpoint, no token ---
	t.Run("protected endpoint rejects no token", func(t *testing.T) {
		status, decoded, _ := doJSON(t, http.MethodGet, env.BaseURL+"/v1/users", nil, "")
		if status != http.StatusUnauthorized {
			t.Fatalf("GET /v1/users with no Authorization header, status = %d, want %d", status, http.StatusUnauthorized)
		}
		if errBody, ok := decoded["error"].(map[string]any); !ok || errBody["code"] != dto.CodeUnauthenticated {
			t.Errorf("error.code = %v, want %q", decoded["error"], dto.CodeUnauthenticated)
		}
		if _, present := decoded["data"]; present {
			t.Error("an unauthenticated request unexpectedly received protected data")
		}
	})

	// --- Scenario 5: protected endpoint, invalid token ---
	t.Run("protected endpoint rejects a malformed token", func(t *testing.T) {
		status, _, _ := doJSON(t, http.MethodGet, env.BaseURL+"/v1/users", nil, "not-a-jwt-at-all")
		if status != http.StatusUnauthorized {
			t.Fatalf("GET /v1/users with a malformed token, status = %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("protected endpoint rejects an invalid signature", func(t *testing.T) {
		// Structurally a real, well-formed JWT — signed with a different
		// key. Rejecting this specifically proves the real
		// signature-verification path runs, not merely a shape/format
		// check on the token string.
		wrongSigner := util.NewJWTSigner("a-completely-different-32-byte-key!!!", 15*time.Minute)
		forged, _, err := wrongSigner.Sign("someone", e2eOrgID, "some-session", nil)
		if err != nil {
			t.Fatalf("Sign (forged token): %v", err)
		}
		status, decoded, _ := doJSON(t, http.MethodGet, env.BaseURL+"/v1/users", nil, forged)
		if status != http.StatusUnauthorized {
			t.Fatalf("GET /v1/users with an invalid-signature token, status = %d, want %d", status, http.StatusUnauthorized)
		}
		if _, present := decoded["data"]; present {
			t.Error("a request with an invalid-signature token unexpectedly received protected data")
		}
	})
}
