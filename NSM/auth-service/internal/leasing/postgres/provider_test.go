package postgres

import (
	"strings"
	"testing"
	"time"
)

// --- credential generation: shape and entropy, no I/O needed ---

func TestGenerateUsername_MatchesExpectedShape(t *testing.T) {
	username, err := generateUsername()
	if err != nil {
		t.Fatalf("generateUsername() error = %v", err)
	}
	if !strings.HasPrefix(username, "vlt_") {
		t.Errorf("generateUsername() = %q, want a \"vlt_\" prefix", username)
	}
	suffix := strings.TrimPrefix(username, "vlt_")
	if len(suffix) != 12 {
		t.Errorf("generateUsername() suffix = %q (%d chars), want 12 hex characters", suffix, len(suffix))
	}
	for _, c := range suffix {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("generateUsername() = %q, contains a non-hex character %q", username, c)
		}
	}
}

// TestGenerateUsername_NeverRepeatsAcrossManyCalls is the "not a
// timestamp, not an incrementing ID" property exercised directly: 10,000
// calls in a tight loop (which a timestamp- or counter-based generator
// would collide on immediately) must never repeat.
func TestGenerateUsername_NeverRepeatsAcrossManyCalls(t *testing.T) {
	seen := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		username, err := generateUsername()
		if err != nil {
			t.Fatalf("generateUsername() error = %v", err)
		}
		if seen[username] {
			t.Fatalf("generateUsername() produced a duplicate: %q", username)
		}
		seen[username] = true
	}
}

func TestGeneratePassword_HighEntropyNoObviousPattern(t *testing.T) {
	password, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword() error = %v", err)
	}
	if len(password) < 40 {
		t.Errorf("generatePassword() = %d characters, want at least 40 (32 random bytes, base64url)", len(password))
	}
	second, err := generatePassword()
	if err != nil {
		t.Fatalf("generatePassword() error = %v", err)
	}
	if password == second {
		t.Error("generatePassword() produced the same value twice in a row")
	}
}

// --- SQL builders: the security checklist's own "SQL safety" section ---

// stripQuotedSpans removes every double-quoted ("...") and single-quoted
// ('...') span from sql, leaving only the bare SQL syntax outside them —
// the fixed keywords and structure buildCreateRoleSQL's own template
// contributes. A forbidden word appearing *inside* a quoted span is
// inert (it's data — an identifier or a literal — never interpreted as
// SQL syntax by Postgres); a forbidden word appearing *outside* one would
// mean it was injected as real syntax. This is a test-only, deliberately
// simple scanner (it does not need to handle every SQL quoting edge
// case, only recognize pq.QuoteIdentifier/pq.QuoteLiteral's own doubled-
// quote escaping well enough to not stop at an escaped quote midway
// through a span).
func stripQuotedSpans(sql string) string {
	var out strings.Builder
	runes := []rune(sql)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == '"' || c == '\'' {
			quote := c
			i++
			for i < len(runes) {
				if runes[i] == quote {
					if i+1 < len(runes) && runes[i+1] == quote {
						i += 2 // an escaped quote inside the span — keep scanning the same span
						continue
					}
					break // the real closing quote
				}
				i++
			}
			continue
		}
		out.WriteRune(c)
	}
	return out.String()
}

// TestBuildCreateRoleSQL_NeverGrantsElevatedAttributes is this package's
// own doc comment's explicit promise, verified directly: no combination
// of inputs to buildCreateRoleSQL can ever produce a statement containing
// any of the objective's named forbidden role attributes as real,
// unquoted SQL syntax — a malicious identifier/password merely
// *containing* one of these words as inert, quoted data (see
// stripQuotedSpans's own doc comment) is a different, already-covered
// case (TestBuildCreateRoleSQL_QuotesMaliciousIdentifiersSafely below),
// not a privilege-escalation risk.
func TestBuildCreateRoleSQL_NeverGrantsElevatedAttributes(t *testing.T) {
	forbidden := []string{"SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS"}
	inputs := []struct{ username, password string }{
		{"vlt_abc123def456", "a-normal-password"},
		{"SUPERUSER", "CREATEDB"},                                             // adversarial: attacker-controlled fields named after the forbidden keywords themselves
		{`vlt_x"; ALTER ROLE vlt_x SUPERUSER; --`, "'; DROP TABLE users; --"}, // adversarial: SQL injection attempt embedded in both fields
	}
	for _, in := range inputs {
		sql := buildCreateRoleSQL(in.username, in.password, time.Now().Add(time.Hour))
		unquoted := strings.ToUpper(stripQuotedSpans(sql))
		for _, word := range forbidden {
			if strings.Contains(unquoted, word) {
				t.Errorf("buildCreateRoleSQL(%q, %q) = %q, forbidden keyword %q appears as real SQL syntax (outside any quoted span)", in.username, in.password, sql, word)
			}
		}
	}
}

// TestBuildCreateRoleSQL_QuotesMaliciousIdentifiersSafely is the
// checklist's own "malicious identifiers" / "SQL injection attempts"
// case: a username containing a double quote or a statement-terminating
// semicolon must come out fully neutralized by pq.QuoteIdentifier —
// never able to break out of the identifier position it was placed in.
func TestBuildCreateRoleSQL_QuotesMaliciousIdentifiersSafely(t *testing.T) {
	malicious := `vlt_evil"; DROP TABLE users; --`
	sql := buildCreateRoleSQL(malicious, "password123", time.Now().Add(time.Hour))

	// pq.QuoteIdentifier doubles every embedded double-quote and wraps
	// the whole thing in one outer pair — the escaped form must appear
	// intact; the raw, unescaped payload must not.
	if !strings.Contains(sql, `vlt_evil""`) {
		t.Errorf("buildCreateRoleSQL(%q, ...) = %q, want the embedded double-quote doubled (pq.QuoteIdentifier's own escaping)", malicious, sql)
	}
	// The real break-out check: once every quoted span is stripped away,
	// nothing of the injection payload (DROP TABLE, the semicolon
	// statement separator) should remain — if it did, that would mean
	// some part of it landed outside a quoted span as real SQL syntax
	// rather than being fully absorbed as inert, escaped identifier data.
	if unquoted := stripQuotedSpans(sql); strings.Contains(unquoted, "DROP") || strings.Contains(unquoted, ";") {
		t.Errorf("buildCreateRoleSQL(%q, ...) = %q, injection payload appears outside the quoted identifier (unquoted remainder = %q)", malicious, sql, unquoted)
	}
}

func TestBuildCreateRoleSQL_QuotesPasswordAsLiteralNotIdentifier(t *testing.T) {
	password := `p'; DROP TABLE users; --`
	sql := buildCreateRoleSQL("vlt_abc123def456", password, time.Now().Add(time.Hour))
	if !strings.Contains(sql, "PASSWORD 'p''") {
		t.Errorf("buildCreateRoleSQL(..., %q, ...) = %q, want the embedded single-quote doubled (pq.QuoteLiteral's own escaping)", password, sql)
	}
}

func TestBuildGrantPrivilegesSQL_QuotesSchemaAndUsernameIdentifiers(t *testing.T) {
	sql := buildGrantPrivilegesSQL([]string{"SELECT"}, `public"; DROP SCHEMA public CASCADE; --`, "vlt_abc123def456")
	if !strings.Contains(sql, `public""`) {
		t.Errorf("buildGrantPrivilegesSQL(...) = %q, want the malicious schema name's embedded quote doubled", sql)
	}
}

func TestBuildRevokeLoginSQL_ProducesNOLOGIN(t *testing.T) {
	sql := buildRevokeLoginSQL("vlt_abc123def456")
	if !strings.Contains(sql, "NOLOGIN") {
		t.Errorf("buildRevokeLoginSQL() = %q, want it to contain NOLOGIN", sql)
	}
	if strings.Contains(strings.ToUpper(sql), "DROP ROLE") {
		t.Errorf("buildRevokeLoginSQL() = %q, want it to never DROP ROLE (see RevokeCredential's own doc comment on why NOLOGIN, not DROP, is this provider's revocation strategy)", sql)
	}
}

func TestBuildRenewSQL_ExtendsValidUntil(t *testing.T) {
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	sql := buildRenewSQL("vlt_abc123def456", until)
	if !strings.Contains(sql, "VALID UNTIL") {
		t.Errorf("buildRenewSQL() = %q, want it to contain VALID UNTIL", sql)
	}
	if !strings.Contains(sql, "2030-01-01") {
		t.Errorf("buildRenewSQL() = %q, want it to contain the new expiry date", sql)
	}
}
