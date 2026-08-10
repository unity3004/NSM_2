//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/dto"
)

// Sprint 2 E2E-03: Logout + Session Revocation.
//
// Endpoint under test: POST /v1/auth/logout (authHandler.logout ->
// service.AuthService.Logout), authenticated by middleware.Auth — the same
// HS256 access-token flow test/e2e/registration_login_protected_test.go's
// Scenario #1 and test/e2e/refresh_rotation_replay_test.go's E2E-02 already
// exercise, kept consistent here for the same reason: it's the one access
// token Register+Login actually issues.
//
// A second logout endpoint exists — POST /v1/auth/logout/current
// (Milestone 6B, logoutHandler -> service.LogoutService.Logout, gated by
// middleware.Authenticate) — and it is deliberately NOT used here, because
// it cannot be reached through any genuine end-to-end flow in the current
// wiring: middleware.AuthenticatedIdentity.SessionID is always empty (the
// Ed25519 access-token claims security.TokenService mints carry no session
// claim at all — see middleware.AuthenticatedIdentity's own doc comment and
// service.LogoutService.Logout's), so a real caller deterministically hits
// service.ErrMissingSessionIdentity and gets 401 UNAUTHENTICATED before the
// handler's own logic ever runs. internal/handler/http/logout_handler_test.go's
// existing coverage of that endpoint only passes because it injects the
// identity directly via middleware.WithIdentity, bypassing real token-to-
// identity derivation entirely. This is a real, pre-existing gap in the
// wired system, not something this suite may fix (see the milestone's own
// "do not redesign the authentication architecture" instruction) — it is
// reported as a remaining security gap instead.
//
// A second, related finding this suite deliberately tests for rather than
// assumes: the legacy endpoint under test here is NOT idempotent. Unlike
// service.LogoutService.Logout (which revokes through *SessionService and
// inherits its own idempotent no-op-on-already-revoked behavior),
// service.AuthService.Logout calls repository.SessionRepository.Revoke
// directly. That method's `UPDATE ... WHERE revoked_at IS NULL` affects
// zero rows the second time, which postgres.checkRowsAffected turns into
// entity.ErrNotFound -> a 404 NOT_FOUND on a repeated logout, not a second
// 204. See TestE2E_Logout_RepeatedLogout below, which asserts the actual
// observed behavior rather than an assumed one.

// registerUser performs registration only (no login) — used by the
// multi-session scenario, which needs to log in as the same user twice.
func registerUser(t *testing.T, env *e2eEnv) (email, userID string) {
	t.Helper()
	client := env.Server.Client()
	suffix := uniqueSuffix(t)
	email = fmt.Sprintf("e2e-logout-%s@example.test", suffix)
	username := "e2e-logout-" + suffix
	orgHeaders := map[string]string{"X-Organization-Id": fixtureOrgID}

	resp, raw := postJSON(t, client, env.Server.URL+"/v1/auth/register", dto.RegisterRequest{
		Username: username, Email: email, Password: testPassword,
	}, orgHeaders)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registerUser: POST /v1/auth/register status = %d, want %d; body = %s", resp.StatusCode, http.StatusCreated, raw)
	}
	var out dto.RegisterResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("registerUser: decode RegisterResponse: %v", err)
	}
	assertNoForbiddenFields(t, "POST /v1/auth/register response", raw, "refresh_token", "access_token")
	t.Cleanup(func() {
		if _, err := env.DB.Exec(`DELETE FROM users WHERE id = $1`, out.ID); err != nil {
			t.Logf("cleanup: delete users row %s: %v", out.ID, err)
		}
	})
	return email, out.ID
}

// loginAs logs in as an already-registered user and returns a fresh
// access/refresh/session triple. Called more than once for the same email
// is exactly how the multi-session scenario gets two independent sessions.
func loginAs(t *testing.T, env *e2eEnv, email string) (accessToken, refreshToken, sessionID string) {
	t.Helper()
	resp, raw := postJSON(t, env.Server.Client(), env.Server.URL+"/v1/auth/login", dto.LoginRequest{
		Email: email, Password: testPassword,
	}, map[string]string{"X-Organization-Id": fixtureOrgID})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loginAs: POST /v1/auth/login status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, raw)
	}
	var out dto.TokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("loginAs: decode TokenResponse: %v", err)
	}
	if out.SessionID == "" {
		t.Fatal("loginAs: login returned no session_id")
	}
	assertNoForbiddenFields(t, "POST /v1/auth/login response", raw)
	return out.AccessToken, out.RefreshToken, out.SessionID
}

// doLogout sends a real POST /v1/auth/logout, authenticated with
// accessToken and optionally carrying refreshToken in the body (the
// endpoint's own documented mechanism for also revoking that token's
// family — see authHandler.logout's doc comment). refreshToken may be
// empty, matching the endpoint's own "body is optional" contract.
func doLogout(t *testing.T, env *e2eEnv, accessToken, refreshToken string) (resp *http.Response, raw []byte) {
	t.Helper()
	headers := map[string]string{"Authorization": "Bearer " + accessToken}
	var body any = struct{}{}
	if refreshToken != "" {
		body = struct {
			RefreshToken string `json:"refresh_token"`
		}{RefreshToken: refreshToken}
	}
	return postJSON(t, env.Server.Client(), env.Server.URL+"/v1/auth/logout", body, headers)
}

// assertLogoutAuditClean is assertAuditLogsClean's auth.logout counterpart
// (that helper is scoped to auth.token_refresh, defined in
// refresh_rotation_replay_test.go) — queried directly against real
// Postgres JSONB, never the in-memory Go struct.
func assertLogoutAuditClean(t *testing.T, env *e2eEnv, sessionID string, secrets ...string) []auditRow {
	t.Helper()
	rows, err := env.DB.Query(
		`SELECT result, metadata::text, actor_id, resource_id FROM audit_logs
		 WHERE action = 'auth.logout' AND resource_id = $1 ORDER BY occurred_at, id`, sessionID)
	if err != nil {
		t.Fatalf("assertLogoutAuditClean: query: %v", err)
	}
	defer rows.Close()

	var out []auditRow
	for rows.Next() {
		var r auditRow
		var metadataText string
		if err := rows.Scan(&r.Result, &metadataText, &r.ActorID, &r.ResourceID); err != nil {
			t.Fatalf("assertLogoutAuditClean: scan: %v", err)
		}
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			if strings.Contains(metadataText, secret) {
				t.Error("audit_logs.metadata contains a secret token value")
			}
			if r.ActorID.Valid && strings.Contains(r.ActorID.String, secret) {
				t.Error("audit_logs.actor_id contains a secret token value")
			}
			if r.ResourceID.Valid && strings.Contains(r.ResourceID.String, secret) {
				t.Error("audit_logs.resource_id contains a secret token value")
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("assertLogoutAuditClean: rows: %v", err)
	}
	return out
}

// TestE2E_LogoutSessionRevocation is the core E2E-03 narrative: Register ->
// Login -> access a protected resource -> Logout -> the session and
// refresh-token family are revoked in real PostgreSQL -> the old refresh
// token can no longer obtain new credentials -> the old access token's own
// real, documented behavior (stateless, not immediately revoked) is proven
// -> a repeated logout is proven to behave exactly as this endpoint
// actually behaves, not as assumed.
func TestE2E_LogoutSessionRevocation(t *testing.T) {
	env := newE2EEnv(t)
	userID, accessToken, refreshToken, sessionID := registerAndLogin(t, env)

	// --- Phase 2: session created in real PostgreSQL ---
	t.Run("SessionCreatedInPostgres", func(t *testing.T) {
		row := fetchSessionRow(t, env, sessionID)
		if row.RevokedAt.Valid {
			t.Fatal("session is already revoked immediately after login")
		}
	})
	if t.Failed() {
		t.Fatal("session was not created as expected; aborting dependent phases")
	}

	// --- Phase 3: baseline access before logout ---
	t.Run("AccessBeforeLogout", func(t *testing.T) {
		url := env.Server.URL + "/v1/users/" + userID
		resp, raw := getWithAuth(t, env.Server.Client(), url, "Bearer "+accessToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/users/{userId} before logout: status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, raw)
		}
		var out dto.UserResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode UserResponse: %v", err)
		}
		if out.ID != userID {
			t.Errorf("UserResponse.ID = %q, want %q — authenticated identity is wrong", out.ID, userID)
		}
	})
	if t.Failed() {
		t.Fatal("baseline access failed; aborting dependent phases")
	}

	// --- Phase 4: logout ---
	t.Run("Logout", func(t *testing.T) {
		resp, raw := doLogout(t, env, accessToken, refreshToken)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("POST /v1/auth/logout: status = %d, want %d; body = %s", resp.StatusCode, http.StatusNoContent, raw)
		}
		if len(raw) != 0 {
			t.Errorf("logout response body = %q, want empty (204 No Content carries nothing, sensitive or otherwise)", raw)
		}
	})
	if t.Failed() {
		t.Fatal("logout did not succeed; aborting dependent phases")
	}

	// --- Phase 5: session + token-family revocation in real PostgreSQL ---
	t.Run("SessionAndTokenFamilyRevokedInPostgres", func(t *testing.T) {
		sessionState := fetchSessionRow(t, env, sessionID)
		if !sessionState.RevokedAt.Valid {
			t.Fatal("session is not revoked in PostgreSQL after logout")
		}
		if sessionState.RevokedReason.String != "logout" {
			t.Errorf("session revoked_reason = %q, want %q", sessionState.RevokedReason.String, "logout")
		}

		tokenState := fetchRefreshTokenRow(t, env, refreshToken)
		if !tokenState.RevokedAt.Valid {
			t.Error("refresh token is not revoked in PostgreSQL after logout")
		}
		if tokenState.RevokedReason.String != "logout" {
			t.Errorf("refresh token revoked_reason = %q, want %q", tokenState.RevokedReason.String, "logout")
		}
	})

	// --- Phase 6: refresh after logout must not yield new credentials ---
	t.Run("RefreshAfterLogout_Rejected", func(t *testing.T) {
		resp, out, raw := doRefresh(t, env, refreshToken)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("refresh succeeded using a refresh token from a logged-out session (body omitted: may contain live tokens)")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("refresh after logout: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		if out.AccessToken != "" || out.RefreshToken != "" {
			t.Error("refresh-after-logout response unexpectedly parsed as a successful TokenResponse")
		}
	})

	// --- Phase 7: access-token behavior after logout — the real, existing
	// architecture, proven rather than assumed. util.JWTSigner.Verify
	// (middleware.Auth's verifier) checks only signature and expiry, never
	// a database or Redis revocation list — confirmed by source
	// inspection, not guessed. Logout revokes the *session* and the
	// refresh-token family; it does not and cannot revoke an already-
	// issued stateless access token before its own short TTL elapses. This
	// subtest proves that reality holds through the real HTTP stack; it
	// does not assert the opposite, and this suite does not change that
	// policy per the milestone's explicit instruction not to. ---
	t.Run("AccessTokenAfterLogout_StatelessUntilExpiry", func(t *testing.T) {
		url := env.Server.URL + "/v1/users/" + userID
		resp, raw := getWithAuth(t, env.Server.Client(), url, "Bearer "+accessToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("old access token rejected after logout (status=%d) — this contradicts this codebase's documented stateless-access-token architecture; "+
				"if access-token revocation was intentionally added, this test must be updated to match the new architecture, not left failing. body = %s", resp.StatusCode, raw)
		}
	})

	// --- Phase 8: repeated logout — the actual observed contract, not an
	// assumed idempotent one. See this file's top-level doc comment for
	// why AuthService.Logout is not idempotent the way LogoutService.Logout
	// is. ---
	t.Run("RepeatedLogout_SafeNonCorruptingResponse", func(t *testing.T) {
		resp, raw := doLogout(t, env, accessToken, "")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("repeated logout: status = %d, want %d (entity.ErrNotFound from Sessions.Revoke's WHERE revoked_at IS NULL affecting zero rows); body = %s",
				resp.StatusCode, http.StatusNotFound, raw)
		}
		var errOut dto.Error
		if err := json.Unmarshal(raw, &errOut); err != nil {
			t.Fatalf("decode error envelope: %v", err)
		}
		if errOut.Error.Code != dto.CodeNotFound {
			t.Errorf("repeated logout error code = %q, want %q", errOut.Error.Code, dto.CodeNotFound)
		}
		// Whatever the status, the session must not have been un-revoked,
		// double-revoked with a different reason, or otherwise corrupted.
		sessionState := fetchSessionRow(t, env, sessionID)
		if !sessionState.RevokedAt.Valid || sessionState.RevokedReason.String != "logout" {
			t.Errorf("session state changed by a repeated logout attempt: revoked=%v reason=%q, want revoked with reason %q",
				sessionState.RevokedAt.Valid, sessionState.RevokedReason.String, "logout")
		}
	})

	// --- Phase 10 (audit) and Phase 11 (Redis): the real, observed
	// behavior — proven below, not assumed — is that service.AuthService.Logout
	// (the endpoint under test, the only logout endpoint any real HTTP flow
	// can reach) writes NO audit_logs row at all. Unlike Login, Refresh,
	// and the unreachable Milestone 6B logout/current endpoint (whose
	// service.LogoutService.Logout does call AuditTx, recording
	// action="auth.logout" — see recordLogoutAudit), AuthServiceDeps has no
	// audit call anywhere inside Logout(); it only emits a zap log line.
	// This means there is currently no way to produce a real, end-to-end-
	// reachable auth.logout audit record anywhere in this system — a
	// genuine compliance gap, reported in the final report's "remaining
	// security gaps" rather than silently fixed here (see this milestone's
	// own "do not redesign the authentication architecture" / "smallest
	// clean changes" instructions). This subtest asserts the actual
	// current behavior specifically so it fails loudly — as a prompt to
	// update the assertion, not just delete it — the day audit logging is
	// intentionally added to this endpoint.
	//
	// Redis: AuthServiceDeps carries no ratelimit dependency for Logout at
	// all (unlike Login/Refresh) — confirmed by source inspection. Logout
	// does not touch Redis in this architecture; there is no state to
	// inspect.
	t.Run("AuditEvents_NoneRecordedByThisEndpoint", func(t *testing.T) {
		entries := assertLogoutAuditClean(t, env, sessionID, refreshToken, accessToken)
		if len(entries) != 0 {
			t.Errorf("auth.logout audit entries for this session = %d, want 0 (AuthService.Logout does not audit-log today) — "+
				"if audit logging was intentionally added to this endpoint, update this assertion to match, don't just delete it", len(entries))
		}
	})
}

// TestE2E_Logout_OtherSessionsUnaffected is Phase 9: two independent real
// logins for the same user produce two independent sessions; logging out
// one must never touch the other. Multi-session support is not invented
// for this test — it already falls out of AuthService.Login creating a
// fresh session on every call with no uniqueness constraint preventing a
// second concurrent one (see migrations/000015_create_sessions_table.up.sql),
// and AuthService.Logout only ever touching the single session named in the
// caller's own signed access-token claims.
func TestE2E_Logout_OtherSessionsUnaffected(t *testing.T) {
	env := newE2EEnv(t)
	email, userID := registerUser(t, env)

	accessA, refreshA, sessionA := loginAs(t, env, email)
	accessB, refreshB, sessionB := loginAs(t, env, email)
	if sessionA == sessionB {
		t.Fatal("two independent logins produced the same session_id")
	}

	resp, raw := doLogout(t, env, accessA, refreshA)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout session A: status = %d, want %d; body = %s", resp.StatusCode, http.StatusNoContent, raw)
	}

	rowA := fetchSessionRow(t, env, sessionA)
	if !rowA.RevokedAt.Valid {
		t.Error("session A was not revoked by its own logout")
	}

	rowB := fetchSessionRow(t, env, sessionB)
	if rowB.RevokedAt.Valid {
		t.Fatal("session B was revoked by logging out session A — logout must be per-session, not per-user, unless this architecture explicitly implements logout-everywhere (it does not)")
	}

	// Session B's own credentials must both still work — proving the
	// isolation at the HTTP-observable level, not only in the database.
	url := env.Server.URL + "/v1/users/" + userID
	getResp, getRaw := getWithAuth(t, env.Server.Client(), url, "Bearer "+accessB)
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("session B's access token rejected after session A's logout: status = %d; body = %s", getResp.StatusCode, getRaw)
	}

	refreshResp, _, refreshRaw := doRefresh(t, env, refreshB)
	if refreshResp.StatusCode != http.StatusOK {
		t.Errorf("session B's refresh token rejected after session A's logout: status = %d; body = %s", refreshResp.StatusCode, refreshRaw)
	}
}
