//go:build e2e

package e2e

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/util"
)

// Sprint 2 E2E-02: Refresh Token Rotation + Replay Detection.
//
// Endpoint under test: POST /v1/auth/refresh (refreshHandler ->
// service.RefreshTokenService.Refresh, Milestone 5B). A second refresh
// endpoint also exists — POST /v1/auth/token/refresh (authHandler.refresh
// -> service.AuthService.RefreshToken, the pre-existing flow Login's own
// access token belongs to) — with materially different behavior: no
// session-state validation (RefreshTokenService.Refresh's ValidateSession
// call has no equivalent there) and no Redis abuse-protection check. Both
// operate on the exact same refresh_tokens table via the same
// repository.RefreshTokenRepository instance, so a token Login mints is
// valid input to either. This suite targets the Milestone 5B endpoint
// because its reuse-detection contract (a distinct TOKEN_REUSE_DETECTED
// error code, proven by the existing internal/handler/http/refresh_handler_test.go)
// and its family-wide revocation of the *unused* rotated descendant (proven
// by internal/service/refresh_token_service_test.go's
// TestRefreshTokenService_Refresh_ReuseTriggersCompromiseResponse) are
// exactly what this milestone's approved design describes. The legacy
// endpoint's own reuse detection is real but untested by this suite — see
// the final report for that gap.

var hexSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// registerAndLogin performs Phase 2 (real registration, then real login)
// and returns everything later phases need. Cleanup (hard-deleting the
// user row) is registered on t itself, not a subtest's T, so it survives
// until every subtest sharing this identity has run — the same ordering
// bug test/e2e/registration_login_protected_test.go's own history already
// found and fixed.
func registerAndLogin(t *testing.T, env *e2eEnv) (userID, accessToken, refreshToken, sessionID string) {
	t.Helper()
	client := env.Server.Client()
	suffix := uniqueSuffix(t)
	email := fmt.Sprintf("e2e-refresh-%s@example.test", suffix)
	username := "e2e-refresh-" + suffix
	orgHeaders := map[string]string{"X-Organization-Id": fixtureOrgID}

	regResp, regRaw := postJSON(t, client, env.Server.URL+"/v1/auth/register", dto.RegisterRequest{
		Username: username, Email: email, Password: testPassword,
	}, orgHeaders)
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("registerAndLogin: POST /v1/auth/register status = %d, want %d; body = %s", regResp.StatusCode, http.StatusCreated, regRaw)
	}
	var regOut dto.RegisterResponse
	if err := json.Unmarshal(regRaw, &regOut); err != nil {
		t.Fatalf("registerAndLogin: decode RegisterResponse: %v", err)
	}
	// Phase 2: the refresh token must never be returned anywhere but the
	// intended mechanism (a successful login response) — registration is
	// not that mechanism.
	assertNoForbiddenFields(t, "POST /v1/auth/register response", regRaw, "refresh_token", "access_token")
	t.Cleanup(func() {
		if _, err := env.DB.Exec(`DELETE FROM users WHERE id = $1`, regOut.ID); err != nil {
			t.Logf("cleanup: delete users row %s: %v", regOut.ID, err)
		}
	})

	loginResp, loginRaw := postJSON(t, client, env.Server.URL+"/v1/auth/login", dto.LoginRequest{
		Email: email, Password: testPassword,
	}, orgHeaders)
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("registerAndLogin: POST /v1/auth/login status = %d, want %d; body = %s", loginResp.StatusCode, http.StatusOK, loginRaw)
	}
	var loginOut dto.TokenResponse
	if err := json.Unmarshal(loginRaw, &loginOut); err != nil {
		t.Fatalf("registerAndLogin: decode TokenResponse: %v", err)
	}
	if loginOut.RefreshToken == "" {
		t.Fatal("registerAndLogin: login returned no refresh token")
	}
	assertNoForbiddenFields(t, "POST /v1/auth/login response", loginRaw)

	return regOut.ID, loginOut.AccessToken, loginOut.RefreshToken, loginOut.SessionID
}

// doRefresh sends a real POST /v1/auth/refresh. The caller must check
// resp.StatusCode before trusting out — on a non-200 response out is the
// zero value, not a parsed error body.
func doRefresh(t *testing.T, env *e2eEnv, rawToken string) (resp *http.Response, out dto.TokenResponse, raw []byte) {
	t.Helper()
	resp, raw = postJSON(t, env.Server.Client(), env.Server.URL+"/v1/auth/refresh", dto.RefreshRequest{RefreshToken: rawToken}, nil)
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("doRefresh: decode TokenResponse: %v", err)
		}
	}
	return resp, out, raw
}

// decodeRefreshError decodes a non-200 refresh response into dto.Error.
// Never called on a 200 response — the whole point is never touching a
// body that might carry live tokens.
func decodeRefreshError(t *testing.T, raw []byte) dto.Error {
	t.Helper()
	var out dto.Error
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	return out
}

type refreshTokenRow struct {
	ID                string
	FamilyID          string
	SessionID         string
	UserID            string
	TokenHash         string
	RevokedAt         sql.NullTime
	RevokedReason     sql.NullString
	ReplacedByTokenID sql.NullString
	ParentTokenID     sql.NullString
}

// fetchRefreshTokenRow queries the real refresh_tokens row for rawToken by
// its hash — the same lookup key GetByTokenHash itself uses (util.HashToken
// is the application's own primitive, not a reimplementation), so a match
// is itself proof the stored token_hash is genuinely SHA-256(rawToken).
// Callers must only assert properties of the returned row (format, equality
// to other DB values, revocation state) — never log TokenHash.
func fetchRefreshTokenRow(t *testing.T, env *e2eEnv, rawToken string) refreshTokenRow {
	t.Helper()
	var row refreshTokenRow
	err := env.DB.QueryRow(
		`SELECT id, family_id, session_id, user_id, token_hash, revoked_at, revoked_reason, replaced_by_token_id, parent_token_id
		 FROM refresh_tokens WHERE token_hash = $1`, util.HashToken(rawToken),
	).Scan(&row.ID, &row.FamilyID, &row.SessionID, &row.UserID, &row.TokenHash,
		&row.RevokedAt, &row.RevokedReason, &row.ReplacedByTokenID, &row.ParentTokenID)
	if err != nil {
		t.Fatalf("fetchRefreshTokenRow: %v", err)
	}
	return row
}

type sessionRow struct {
	RevokedAt     sql.NullTime
	RevokedReason sql.NullString
}

func fetchSessionRow(t *testing.T, env *e2eEnv, sessionID string) sessionRow {
	t.Helper()
	var row sessionRow
	err := env.DB.QueryRow(`SELECT revoked_at, revoked_reason FROM sessions WHERE id = $1`, sessionID).
		Scan(&row.RevokedAt, &row.RevokedReason)
	if err != nil {
		t.Fatalf("fetchSessionRow: %v", err)
	}
	return row
}

type auditRow struct {
	Result     string
	ActorID    sql.NullString
	ResourceID sql.NullString
}

// assertAuditLogsClean queries every real auth.token_refresh audit_logs row
// for sessionID and fails the test if any text field (metadata, actor_id,
// resource_id) contains any of secrets — proving the never-carries-a-secret
// property against Postgres's own JSONB serialization, not just the Go
// struct in memory (which internal/service/refresh_token_service_test.go's
// TestRefreshTokenService_Refresh_AuditNeverContainsToken already covers).
func assertAuditLogsClean(t *testing.T, env *e2eEnv, sessionID string, secrets ...string) []auditRow {
	t.Helper()
	rows, err := env.DB.Query(
		`SELECT result, metadata::text, actor_id, resource_id FROM audit_logs
		 WHERE action = 'auth.token_refresh' AND resource_id = $1 ORDER BY occurred_at, id`, sessionID)
	if err != nil {
		t.Fatalf("assertAuditLogsClean: query: %v", err)
	}
	defer rows.Close()

	var out []auditRow
	for rows.Next() {
		var r auditRow
		var metadataText string
		if err := rows.Scan(&r.Result, &metadataText, &r.ActorID, &r.ResourceID); err != nil {
			t.Fatalf("assertAuditLogsClean: scan: %v", err)
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
		t.Fatalf("assertAuditLogsClean: rows: %v", err)
	}
	return out
}

// TestE2E_RefreshTokenRotationAndReplayDetection is the core E2E-02
// narrative: Login -> Refresh Token A -> POST /refresh -> Refresh Token B
// -> Token A replayed -> replay detected -> Token B (an unused, otherwise
// legitimate descendant) also invalidated by family-wide revocation ->
// session revoked. Every step is one real HTTP request against the real
// router; database state is inspected directly afterward, never through
// Go-level service/repository calls.
func TestE2E_RefreshTokenRotationAndReplayDetection(t *testing.T) {
	env := newE2EEnv(t)
	userID, accessTokenA, refreshTokenA, sessionID := registerAndLogin(t, env)

	// --- Phase 7: token hash storage, before anything rotates A ---
	t.Run("TokenHashStorage_NotPlaintext", func(t *testing.T) {
		row := fetchRefreshTokenRow(t, env, refreshTokenA)
		if row.TokenHash == refreshTokenA {
			t.Fatal("refresh_tokens.token_hash equals the plaintext raw token")
		}
		if !hexSHA256Pattern.MatchString(row.TokenHash) {
			t.Error("refresh_tokens.token_hash is not a 64-character lowercase hex SHA-256 digest")
		}
		if row.FamilyID == "" {
			t.Error("refresh_tokens.family_id is empty")
		}
		if row.SessionID != sessionID {
			t.Errorf("refresh_tokens.session_id = %q, want %q (the login session)", row.SessionID, sessionID)
		}
		if row.UserID != userID {
			t.Errorf("refresh_tokens.user_id = %q, want %q", row.UserID, userID)
		}
		if row.RevokedAt.Valid {
			t.Error("Token A is already revoked before any refresh happened")
		}
	})
	if t.Failed() {
		t.Fatal("token-hash-storage checks failed; aborting dependent phases")
	}

	// --- Phase 3: first refresh, real rotation ---
	var refreshTokenB, accessTokenB string
	t.Run("FirstRefresh_Rotation", func(t *testing.T) {
		resp, out, raw := doRefresh(t, env, refreshTokenA)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /v1/auth/refresh (Token A): status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, raw)
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
			t.Errorf("response session_id = %q, want %q (Phase 10: binding must survive rotation)", out.SessionID, sessionID)
		}
		assertNoForbiddenFields(t, "POST /v1/auth/refresh response", raw)
		refreshTokenB = out.RefreshToken
		accessTokenB = out.AccessToken

		// Access token B validated with the application's own real
		// verification mechanism (the exact TokenService instance the
		// router's middleware.Authenticate would use) — never a
		// hand-rolled or disabled check.
		claims, err := env.AccessTokens.ValidateAccessToken(accessTokenB, env.AccessTokenAudience)
		if err != nil {
			t.Fatalf("access token B failed real verification: %v", err)
		}
		if claims.Subject != userID {
			t.Errorf("access token B sub = %q, want %q", claims.Subject, userID)
		}

		// Real PostgreSQL: Token A is revoked-with-replacement; Token B
		// exists, shares Token A's family, and is not itself revoked yet.
		aRow := fetchRefreshTokenRow(t, env, refreshTokenA)
		if !aRow.RevokedAt.Valid {
			t.Error("Token A is not marked revoked after rotation")
		}
		if aRow.RevokedReason.String != "rotation" {
			t.Errorf("Token A revoked_reason = %q, want %q", aRow.RevokedReason.String, "rotation")
		}
		if !aRow.ReplacedByTokenID.Valid {
			t.Error("Token A has no replaced_by_token_id after rotation")
		}

		bRow := fetchRefreshTokenRow(t, env, refreshTokenB)
		if aRow.ReplacedByTokenID.Valid && aRow.ReplacedByTokenID.String != bRow.ID {
			t.Error("Token A's replaced_by_token_id does not point at Token B's actual row")
		}
		if bRow.FamilyID != aRow.FamilyID {
			t.Errorf("Token B family_id = %q, want %q (Token A's) — rotation must preserve the family", bRow.FamilyID, aRow.FamilyID)
		}
		if bRow.ParentTokenID.String != aRow.ID {
			t.Errorf("Token B parent_token_id = %v, want %q (Token A's id)", bRow.ParentTokenID, aRow.ID)
		}
		if bRow.RevokedAt.Valid {
			t.Error("Token B is already revoked immediately after being issued")
		}
	})
	if t.Failed() {
		t.Fatal("first refresh did not succeed; aborting dependent phases")
	}

	// --- Phase 4: replay Token A ---
	t.Run("ReplayDetection_OldTokenRejected", func(t *testing.T) {
		resp, out, raw := doRefresh(t, env, refreshTokenA)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("replaying Token A succeeded — replay detection did not trigger (body omitted: may contain live tokens)")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("replaying Token A: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		errOut := decodeRefreshError(t, raw)
		// The specific security event, not just "some 401": a generic
		// invalid/expired token and an actual replay must be
		// distinguishable to anything consuming this API's audit trail.
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

	// --- Phase 5: token-family behavior — B must die too ---
	t.Run("TokenFamilyRevoked_UnusedDescendantAlsoInvalid", func(t *testing.T) {
		resp, _, raw := doRefresh(t, env, refreshTokenB)
		if resp.StatusCode == http.StatusOK {
			t.Fatal("Token B (an unused, otherwise-legitimate descendant) still refreshed successfully after family-wide revocation (body omitted)")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Token B after family revocation: status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}

		bRow := fetchRefreshTokenRow(t, env, refreshTokenB)
		if !bRow.RevokedAt.Valid {
			t.Error("Token B is not revoked in PostgreSQL after family-wide reuse revocation")
		}
		if bRow.RevokedReason.String != "reuse_detected" {
			t.Errorf("Token B revoked_reason = %q, want %q", bRow.RevokedReason.String, "reuse_detected")
		}
	})

	// --- Phase 6: session state ---
	t.Run("SessionRevokedAfterReplay", func(t *testing.T) {
		row := fetchSessionRow(t, env, sessionID)
		if !row.RevokedAt.Valid {
			t.Error("session is not revoked in PostgreSQL after replay detection")
		}
		if row.RevokedReason.String != "reuse_detected" {
			t.Errorf("session revoked_reason = %q, want %q", row.RevokedReason.String, "reuse_detected")
		}
	})

	// --- Phase 12: audit events, real Postgres JSONB, never a secret ---
	t.Run("AuditEvents", func(t *testing.T) {
		entries := assertAuditLogsClean(t, env, sessionID, refreshTokenA, refreshTokenB, accessTokenA, accessTokenB)
		if len(entries) < 3 {
			t.Fatalf("auth.token_refresh audit entries for this session = %d, want at least 3 (success, replay, descendant-revoked)", len(entries))
		}
		var sawSuccess, sawFailure bool
		for _, e := range entries {
			switch e.Result {
			case "success":
				sawSuccess = true
				if !e.ActorID.Valid || e.ActorID.String != userID {
					t.Errorf("success audit entry actor_id = %v, want %q", e.ActorID, userID)
				}
			case "failure":
				sawFailure = true
			}
			if !e.ResourceID.Valid || e.ResourceID.String != sessionID {
				t.Errorf("audit entry resource_id = %v, want %q", e.ResourceID, sessionID)
			}
		}
		if !sawSuccess {
			t.Error("no successful auth.token_refresh audit entry was recorded")
		}
		if !sawFailure {
			t.Error("no failed auth.token_refresh audit entry was recorded")
		}
	})
}

// TestE2E_RefreshToken_NegativeInputs covers Phases 8 and 9: an access
// token submitted where a refresh token belongs, a malformed value, a
// random value, and (via direct, real-Postgres precondition setup — not a
// bypassed check) an expired one. Each subtest is independent and none
// mutates state another depends on, except ExpiredToken, which backdates
// its own dedicated token's expiry and touches nothing else.
func TestE2E_RefreshToken_NegativeInputs(t *testing.T) {
	env := newE2EEnv(t)
	_, accessTokenA, refreshTokenA, _ := registerAndLogin(t, env)

	assertRejectedGenerically := func(t *testing.T, resp *http.Response, raw []byte, wantCode string) {
		t.Helper()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("request unexpectedly succeeded (body omitted: may contain live tokens)")
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, raw)
		}
		errOut := decodeRefreshError(t, raw)
		if errOut.Error.Code != wantCode {
			t.Errorf("error code = %q, want %q", errOut.Error.Code, wantCode)
		}
		// No internal detail — database errors, stack traces, hashes —
		// ever reaches the client.
		lower := strings.ToLower(errOut.Error.Message)
		for _, leak := range []string{"sql", "pq:", "runtime.", "goroutine", "panic", ".go:", "internal server", "stack trace"} {
			if strings.Contains(lower, leak) {
				t.Errorf("error message leaks internal detail (%q): %q", leak, errOut.Error.Message)
			}
		}
	}

	// --- Phase 8: token-type confusion ---
	t.Run("AccessTokenAsRefreshToken_Rejected", func(t *testing.T) {
		resp, _, raw := doRefresh(t, env, accessTokenA)
		// A JWT's SHA-256 will never match a stored opaque refresh-token
		// hash, so this collapses to the same "not found" path as any
		// other unknown token — proving the type confusion has no special
		// acceptance path, not asserting a specific distinguishing code.
		assertRejectedGenerically(t, resp, raw, dto.CodeTokenExpired)
	})

	// --- Phase 9: malformed / random ---
	t.Run("MalformedToken_Rejected", func(t *testing.T) {
		resp, _, raw := doRefresh(t, env, "not-a-real-refresh-token!!")
		assertRejectedGenerically(t, resp, raw, dto.CodeTokenExpired)
	})

	t.Run("RandomToken_Rejected", func(t *testing.T) {
		random, err := util.NewOpaqueToken()
		if err != nil {
			t.Fatalf("NewOpaqueToken: %v", err)
		}
		resp, _, raw := doRefresh(t, env, random)
		assertRejectedGenerically(t, resp, raw, dto.CodeTokenExpired)
	})

	// --- Phase 9: expired (real precondition via direct SQL, real check via HTTP) ---
	t.Run("ExpiredToken_Rejected", func(t *testing.T) {
		// expires_at must stay after issued_at (ck_refresh_tokens_expiry_future)
		// while still landing in the past by the time the HTTP call below
		// runs — a 1ms window issued_at, then a short real sleep, achieves
		// both without violating the schema's own constraint.
		if _, err := env.DB.Exec(
			`UPDATE refresh_tokens SET expires_at = issued_at + interval '1 millisecond' WHERE token_hash = $1`,
			util.HashToken(refreshTokenA),
		); err != nil {
			t.Fatalf("backdate refresh token expiry: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
		resp, _, raw := doRefresh(t, env, refreshTokenA)
		assertRejectedGenerically(t, resp, raw, dto.CodeTokenExpired)
	})
}

// TestE2E_RefreshToken_ConcurrentRefreshCannotDoubleRotate is Phase 11: N
// real, concurrent HTTP requests presenting the exact same refresh token
// must not both rotate successfully. The winner is not determined in
// advance — only that there is exactly one.
func TestE2E_RefreshToken_ConcurrentRefreshCannotDoubleRotate(t *testing.T) {
	env := newE2EEnv(t)
	_, _, refreshTokenA, _ := registerAndLogin(t, env)

	const concurrency = 10
	var wg sync.WaitGroup
	statuses := make([]int, concurrency)
	bodies := make([][]byte, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, raw := postJSON(t, env.Server.Client(), env.Server.URL+"/v1/auth/refresh", dto.RefreshRequest{RefreshToken: refreshTokenA}, nil)
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
		t.Fatalf("successful concurrent rotations = %d, want exactly 1 — a single refresh token must not produce two independently valid descendants under a race", successCount)
	}

	// Real PostgreSQL: Token A was revoked exactly once, by rotation, and
	// exactly one row was ever created as its child — Rotate's own
	// transaction (INSERT next, then UPDATE current WHERE revoked_at IS
	// NULL, rolling both back together if the UPDATE affects zero rows;
	// see postgres.refreshTokenRepository.Rotate) guarantees every losing
	// goroutine's INSERT is rolled back, not merely left unreferenced. This
	// is checked without a revoked_at filter, deliberately: a row can
	// legitimately be revoked *after* being created (see below), so
	// "exactly one row was ever created" is the timing-independent
	// invariant, not "exactly one is currently unrevoked."
	aRow := fetchRefreshTokenRow(t, env, refreshTokenA)
	if !aRow.RevokedAt.Valid || aRow.RevokedReason.String != "rotation" {
		t.Fatalf("Token A revoked_at/reason = %v/%q, want revoked with reason %q", aRow.RevokedAt, aRow.RevokedReason.String, "rotation")
	}
	var childCount int
	if err := env.DB.QueryRow(
		`SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND parent_token_id = $2`,
		aRow.FamilyID, aRow.ID,
	).Scan(&childCount); err != nil {
		t.Fatalf("count children of Token A: %v", err)
	}
	if childCount != 1 {
		t.Errorf("rows ever created as Token A's child = %d, want exactly 1 — a losing goroutine's INSERT must roll back with its failed UPDATE, never persist as an orphan", childCount)
	}

	// Deliberately not asserted: that the winning goroutine's new refresh
	// token is still usable after the race. A goroutine that reaches
	// GetByTokenHash *after* the winner has already committed sees an
	// AlreadyRotated token — which is byte-for-byte what a genuine attacker
	// replaying a stolen token also looks like — and this implementation
	// has no grace window to tell the two apart (see
	// RefreshTokenService.Refresh's AlreadyRotated branch). It correctly,
	// safely revokes the whole family, including the winner's own
	// brand-new child. Observed directly in this run: the winning token
	// can end up TOKEN_EXPIRED moments after being issued. That is this
	// codebase's real, existing, fail-safe security policy — "when a
	// request is indistinguishable from replay, treat it as replay" — not
	// a bug this test may contradict or weaken by asserting a specific
	// timing-dependent outcome for it.
}
