//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/util"
)

// Legacy refresh coverage: POST /v1/auth/token/refresh (authHandler.refresh
// -> service.AuthService.RefreshToken) — Login's own direct sibling, issuing
// the same HS256 access token (util.JWTSigner) Register+Login's own baseline
// flow (test/e2e/registration_login_protected_test.go) already verifies,
// and operating on the exact same refresh_tokens table/repository instance
// as POST /v1/auth/refresh (RefreshTokenService, already covered by
// test/e2e/refresh_rotation_replay_test.go's E2E-02 suite). This file
// deliberately does not re-derive what's already proven identical between
// the two endpoints (both share postgres.refreshTokenRepository.Rotate's
// row-locking, both revoke the whole family on reuse, both return the same
// distinct TOKEN_REUSE_DETECTED code) — see AuthService.RefreshToken's own
// source for the shared mechanism. It focuses on what's real, observed, and
// different, found by inspection rather than assumed:
//
//  1. Session-validity check during rotation. RefreshTokenService.Refresh
//     calls SessionService.ValidateSession before rotating (proven by
//     refresh_rotation_replay_test.go's logout-then-refresh scenarios,
//     transitively); AuthService.RefreshToken did not — it only checked the
//     *token's own* revoked/expired state, so a session an administrator
//     force-revoked independently of its refresh tokens (e.g.
//     UserService.DisableUser's RevokeAllForUser call, Sprint 2.7) did not
//     stop this endpoint from minting a fresh access token from an
//     as-yet-unrevoked refresh token. Found for real by
//     TestUserManagement_FullLifecycle (user_role_management_test.go)
//     exercising a real disable-then-refresh sequence against the live
//     endpoint, and fixed the same way RefreshTokenService.Refresh already
//     did it: AuthService.RefreshToken now fetches the session and rejects
//     with TOKEN_EXPIRED if it is revoked or expired, before rotating.
//     TestE2E_LegacyRefreshToken_SessionValidityEnforced proves the fixed
//     behavior directly.
//  2. No Redis-backed rate limiting at all — AuthServiceDeps.RefreshToken
//     never touches AbuseProtection (unlike RefreshTokenService.Refresh's
//     own IP-scoped pre-check).
//  3. Audit logging — a real gap this suite found (RefreshToken wrote no
//     audit_logs row at all, the same missing-audit-write pattern
//     AuthService.Logout had before it was fixed) has since been fixed:
//     see service.AuthService.recordRefreshAudit, which uses the same
//     "auth.token_refresh" action name RefreshTokenService.recordRefreshAudit
//     already uses for the Milestone 5B flow. AuditEvents below now
//     verifies the real, current behavior.

// doLegacyRefresh sends a real POST /v1/auth/token/refresh.
func doLegacyRefresh(t *testing.T, env *e2eEnv, rawToken string) (resp *http.Response, out dto.TokenResponse, raw []byte) {
	t.Helper()
	resp, raw = postJSON(t, env.Server.Client(), env.Server.URL+"/v1/auth/token/refresh", dto.RefreshRequest{RefreshToken: rawToken}, nil)
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("doLegacyRefresh: decode TokenResponse: %v", err)
		}
	}
	return resp, out, raw
}

// TestE2E_LegacyRefreshTokenRotationAndReplayDetection mirrors E2E-02's
// core narrative against the legacy endpoint: Login -> Refresh Token A ->
// POST /v1/auth/token/refresh -> Refresh Token B -> Token A replayed ->
// replay detected -> Token B (an unused, otherwise legitimate descendant)
// also invalidated by family-wide revocation -> session revoked -> a real
// auth.token_refresh audit trail exists for the attempts, in real Postgres.
func TestE2E_LegacyRefreshTokenRotationAndReplayDetection(t *testing.T) {
	env := newE2EEnv(t)
	userID, _, refreshTokenA, sessionID := registerAndLogin(t, env)

	t.Run("TokenHashStorage_NotPlaintext", func(t *testing.T) {
		row := fetchRefreshTokenRow(t, env, refreshTokenA)
		if row.TokenHash == refreshTokenA {
			t.Fatal("refresh_tokens.token_hash equals the plaintext raw token")
		}
		if !hexSHA256Pattern.MatchString(row.TokenHash) {
			t.Error("refresh_tokens.token_hash is not a 64-character lowercase hex SHA-256 digest")
		}
		if row.SessionID != sessionID {
			t.Errorf("refresh_tokens.session_id = %q, want %q", row.SessionID, sessionID)
		}
		if row.UserID != userID {
			t.Errorf("refresh_tokens.user_id = %q, want %q", row.UserID, userID)
		}
	})
	if t.Failed() {
		t.Fatal("token-hash-storage checks failed; aborting dependent phases")
	}

	var refreshTokenB, accessTokenB string
	t.Run("FirstRefresh_Rotation", func(t *testing.T) {
		resp, out, raw := doLegacyRefresh(t, env, refreshTokenA)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /v1/auth/token/refresh (Token A): status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, raw)
		}
		if out.AccessToken == "" {
			t.Error("no new access token issued")
		}
		if out.RefreshToken == "" {
			t.Fatal("no new refresh token issued")
		}
		if out.RefreshToken == refreshTokenA {
			t.Fatal("rotation did not occur: the same refresh token was returned")
		}
		if out.SessionID != sessionID {
			t.Errorf("response session_id = %q, want %q", out.SessionID, sessionID)
		}
		assertNoForbiddenFields(t, "POST /v1/auth/token/refresh response", raw)
		refreshTokenB = out.RefreshToken
		accessTokenB = out.AccessToken

		// The legacy endpoint mints the same HS256 access token Login
		// itself mints — verified with the application's own real
		// verification mechanism, the exact util.JWTSigner instance
		// middleware.Auth uses.
		claims, err := env.Tokens.Verify(accessTokenB)
		if err != nil {
			t.Fatalf("legacy access token B failed real verification: %v", err)
		}
		if claims.Subject != userID {
			t.Errorf("access token B sub = %q, want %q", claims.Subject, userID)
		}
		if claims.SessionID != sessionID {
			t.Errorf("access token B sid = %q, want %q", claims.SessionID, sessionID)
		}

		aRow := fetchRefreshTokenRow(t, env, refreshTokenA)
		if !aRow.RevokedAt.Valid || aRow.RevokedReason.String != "rotation" {
			t.Errorf("Token A revoked_at/reason = %v/%q, want revoked with reason %q", aRow.RevokedAt, aRow.RevokedReason.String, "rotation")
		}
		bRow := fetchRefreshTokenRow(t, env, refreshTokenB)
		if bRow.FamilyID != aRow.FamilyID {
			t.Errorf("Token B family_id = %q, want %q (Token A's)", bRow.FamilyID, aRow.FamilyID)
		}
		if bRow.RevokedAt.Valid {
			t.Error("Token B is already revoked immediately after being issued")
		}
	})
	if t.Failed() {
		t.Fatal("first refresh did not succeed; aborting dependent phases")
	}

	t.Run("ReplayDetection_OldTokenRejected", func(t *testing.T) {
		resp, out, raw := doLegacyRefresh(t, env, refreshTokenA)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("replaying Token A succeeded — replay detection did not trigger (body omitted: may contain live tokens)")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("replaying Token A: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		var errOut dto.Error
		if err := json.Unmarshal(raw, &errOut); err != nil {
			t.Fatalf("decode error envelope: %v", err)
		}
		if errOut.Error.Code != dto.CodeTokenReuseDetected {
			t.Errorf("error code = %q, want %q — replay was not specifically detected", errOut.Error.Code, dto.CodeTokenReuseDetected)
		}
		if out.AccessToken != "" || out.RefreshToken != "" {
			t.Error("replay response unexpectedly parsed as a successful TokenResponse")
		}
	})
	if t.Failed() {
		t.Fatal("replay-detection assertions failed; aborting dependent phases")
	}

	t.Run("TokenFamilyRevoked_UnusedDescendantAlsoInvalid", func(t *testing.T) {
		resp, _, raw := doLegacyRefresh(t, env, refreshTokenB)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("Token B (an unused, otherwise-legitimate descendant) still refreshed successfully after family-wide revocation (body omitted)")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Token B after family revocation: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		bRow := fetchRefreshTokenRow(t, env, refreshTokenB)
		if !bRow.RevokedAt.Valid || bRow.RevokedReason.String != "reuse_detected" {
			t.Errorf("Token B revoked_at/reason = %v/%q, want revoked with reason %q", bRow.RevokedAt, bRow.RevokedReason.String, "reuse_detected")
		}
	})

	t.Run("SessionRevokedAfterReplay", func(t *testing.T) {
		row := fetchSessionRow(t, env, sessionID)
		if !row.RevokedAt.Valid || row.RevokedReason.String != "reuse_detected" {
			t.Errorf("session revoked_at/reason = %v/%q, want revoked with reason %q", row.RevokedAt, row.RevokedReason.String, "reuse_detected")
		}
	})

	// Audit logging was a real, missing-write gap this suite found; it has
	// since been fixed (service.AuthService.recordRefreshAudit) — this now
	// verifies the real, current behavior against real Postgres JSONB,
	// reusing the same assertAuditLogsClean helper
	// refresh_rotation_replay_test.go's own AuditEvents subtest uses (both
	// endpoints share the "auth.token_refresh" action name).
	t.Run("AuditEvents", func(t *testing.T) {
		entries := assertAuditLogsClean(t, env, sessionID, refreshTokenA, refreshTokenB, accessTokenB)
		if len(entries) == 0 {
			t.Fatal("no auth.token_refresh audit entries were recorded")
		}
		found := false
		for _, e := range entries {
			if e.Result != "success" {
				continue
			}
			found = true
			if !e.ActorID.Valid {
				t.Error("success audit entry has no actor_id")
			}
			if !e.ResourceID.Valid || e.ResourceID.String != sessionID {
				t.Errorf("audit entry resource_id = %v, want %q", e.ResourceID, sessionID)
			}
		}
		if !found {
			t.Error("no successful auth.token_refresh audit entry was recorded")
		}
	})
}

// TestE2E_LegacyRefreshToken_SessionValidityEnforced proves the fixed
// behavior documented in this file's top-level comment: a session revoked
// independently of its refresh tokens (e.g. an administrator disabling the
// user, or force-revoking the session directly) now stops this endpoint
// from minting a fresh access token, exactly like RefreshTokenService.Refresh
// already enforced. The session state is arranged directly via real SQL —
// a legitimate test precondition standing in for UserService.DisableUser's
// real effect, not a bypassed check — and the actual rejection decision is
// still made by the real HTTP endpoint.
func TestE2E_LegacyRefreshToken_SessionValidityEnforced(t *testing.T) {
	env := newE2EEnv(t)
	_, _, refreshToken, sessionID := registerAndLogin(t, env)

	if _, err := env.DB.Exec(`UPDATE sessions SET revoked_at = now(), revoked_reason = 'admin_revoked' WHERE id = $1`, sessionID); err != nil {
		t.Fatalf("revoke session directly: %v", err)
	}
	row := fetchSessionRow(t, env, sessionID)
	if !row.RevokedAt.Valid {
		t.Fatal("test setup failed: session was not actually revoked")
	}

	resp, _, raw := doLegacyRefresh(t, env, refreshToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /v1/auth/token/refresh with a token whose session is independently revoked: status = %d, want %d; body = %s",
			resp.StatusCode, http.StatusUnauthorized, raw)
	}
	var errOut dto.Error
	if err := json.Unmarshal(raw, &errOut); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if errOut.Error.Code != dto.CodeTokenExpired {
		t.Errorf("error code = %q, want %q", errOut.Error.Code, dto.CodeTokenExpired)
	}
}

// TestE2E_LegacyRefreshToken_NegativeInputs mirrors E2E-02's negative-input
// coverage (token-type confusion, malformed, random) against the legacy
// endpoint.
func TestE2E_LegacyRefreshToken_NegativeInputs(t *testing.T) {
	env := newE2EEnv(t)
	_, accessToken, _, _ := registerAndLogin(t, env)

	assertRejected := func(t *testing.T, resp *http.Response, raw []byte) {
		t.Helper()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("request unexpectedly succeeded (body omitted: may contain live tokens)")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		var errOut dto.Error
		if err := json.Unmarshal(raw, &errOut); err != nil {
			t.Fatalf("decode error envelope: %v", err)
		}
		if errOut.Error.Code != dto.CodeTokenExpired {
			t.Errorf("error code = %q, want %q", errOut.Error.Code, dto.CodeTokenExpired)
		}
	}

	t.Run("AccessTokenAsRefreshToken_Rejected", func(t *testing.T) {
		resp, _, raw := doLegacyRefresh(t, env, accessToken)
		assertRejected(t, resp, raw)
	})

	t.Run("MalformedToken_Rejected", func(t *testing.T) {
		resp, _, raw := doLegacyRefresh(t, env, "not-a-real-refresh-token!!")
		assertRejected(t, resp, raw)
	})

	t.Run("RandomToken_Rejected", func(t *testing.T) {
		random, err := util.NewOpaqueToken()
		if err != nil {
			t.Fatalf("NewOpaqueToken: %v", err)
		}
		resp, _, raw := doLegacyRefresh(t, env, random)
		assertRejected(t, resp, raw)
	})
}

// TestE2E_LegacyRefreshToken_ConcurrentRefreshCannotDoubleRotate proves the
// same invariant refresh_rotation_replay_test.go's own concurrent test
// proves for the Milestone 5B endpoint — real, concurrent HTTP requests
// presenting the exact same refresh token must not both rotate — against
// this endpoint directly rather than assuming the shared
// postgres.refreshTokenRepository.Rotate transaction makes it automatic.
func TestE2E_LegacyRefreshToken_ConcurrentRefreshCannotDoubleRotate(t *testing.T) {
	env := newE2EEnv(t)
	_, _, refreshToken, _ := registerAndLogin(t, env)

	const concurrency = 10
	var wg sync.WaitGroup
	statuses := make([]int, concurrency)
	bodies := make([][]byte, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, raw := postJSON(t, env.Server.Client(), env.Server.URL+"/v1/auth/token/refresh", dto.RefreshRequest{RefreshToken: refreshToken}, nil)
			statuses[i] = resp.StatusCode
			bodies[i] = raw
		}(i)
	}
	wg.Wait()

	successCount := 0
	for i, status := range statuses {
		switch status {
		case http.StatusOK:
			successCount++
			var out dto.TokenResponse
			if err := json.Unmarshal(bodies[i], &out); err != nil {
				t.Fatalf("decode successful concurrent response: %v", err)
			}
			if out.RefreshToken == "" {
				t.Error("a successful concurrent response carried no refresh token")
			}
		case http.StatusUnauthorized:
			// expected for every loser
		default:
			t.Errorf("concurrent refresh %d: unexpected status %d; body = %s", i, status, bodies[i])
		}
	}
	if successCount != 1 {
		t.Fatalf("successful concurrent rotations = %d, want exactly 1", successCount)
	}

	row := fetchRefreshTokenRow(t, env, refreshToken)
	if !row.RevokedAt.Valid || row.RevokedReason.String != "rotation" {
		t.Fatalf("original token revoked_at/reason = %v/%q, want revoked with reason %q", row.RevokedAt, row.RevokedReason.String, "rotation")
	}
	var childCount int
	if err := env.DB.QueryRow(
		`SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND parent_token_id = $2`,
		row.FamilyID, row.ID,
	).Scan(&childCount); err != nil {
		t.Fatalf("count children: %v", err)
	}
	if childCount != 1 {
		t.Errorf("rows ever created as the original token's child = %d, want exactly 1", childCount)
	}
}
