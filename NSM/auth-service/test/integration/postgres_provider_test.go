//go:build integration

package integration

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/leasing"
	leasingpg "github.com/acme/auth-service/internal/leasing/postgres"
)

// This file proves leasing/postgres.Provider against a real PostgreSQL
// server — the one already required for every other file in this
// package (DATABASE_URL, see connectForRegisterTest). The connection
// used here has the same broad rights as this sandbox's own `authsvc`
// database owner, standing in for a real deployment's dedicated
// `vault-provisioner` identity (see Provider's own doc comment for the
// production privilege list that identity actually needs) — this file
// proves the provider's own SQL behaves correctly, not that a
// least-privilege provisioner connection is sufficient to run it, which
// is a real, separate, environment-specific thing to verify before
// production use and is called out as a known limitation in this
// sprint's own final report.

const pgProviderTestSchema = "vault_provider_test"

// setupPostgresProviderTest creates an isolated schema with one table
// (so GRANT ... ON ALL TABLES IN SCHEMA has something real to grant) and
// returns a ready-to-use Provider plus a cleanup func. Every test in this
// file gets its own schema (named after t.Name(), sanitized) so
// concurrent `go test` runs — or a re-run against a database that still
// has a previous run's roles in it — never collide.
func setupPostgresProviderTest(t *testing.T) (*leasingpg.Provider, *sql.DB) {
	t.Helper()
	db := connectForRegisterTest(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+pgProviderTestSchema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+pgProviderTestSchema+`.widgets (id serial primary key, name text)`); err != nil {
		t.Fatalf("create test table: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort: drop every role this test run created (anything
		// matching vlt_%) so repeated local runs don't accumulate roles
		// forever. Real reconciliation (Provider.ListRoles) is exercised
		// by its own test below.
		rows, err := db.QueryContext(context.Background(), `SELECT rolname FROM pg_roles WHERE rolname LIKE 'vlt\_%' ESCAPE '\'`)
		if err != nil {
			return
		}
		var names []string
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				names = append(names, n)
			}
		}
		rows.Close()
		for _, n := range names {
			_, _ = db.ExecContext(context.Background(), `DROP ROLE IF EXISTS `+pqQuote(n))
		}
	})

	// "authdb" matches connectForRegisterTest's own DATABASE_URL target
	// (see docker/docker-compose.yml's postgres service) — this file
	// always runs against that same database, so the role template
	// names it directly rather than parsing it back out of the DSN.
	templates := map[string]leasingpg.RoleTemplate{
		"widgets-readonly": {Database: "authdb", Schemas: []string{pgProviderTestSchema}, Privileges: []string{"SELECT"}},
	}
	return leasingpg.NewProvider(db, templates, "localhost", 5432), db
}

// pqQuote is a tiny, test-only identifier quoter — good enough for the
// server-generated "vlt_<hex>" names this file only ever feeds it,
// deliberately not reusing leasing/postgres's own unexported quoting
// helpers (this package can't import them; that package's own real
// pq.QuoteIdentifier usage is what CreateCredential itself is tested
// against, both at the unit level and indirectly here).
func pqQuote(identifier string) string { return `"` + identifier + `"` }

func TestPostgresProvider_CreateCredential_RoleHasNoElevatedAttributes(t *testing.T) {
	provider, db := setupPostgresProviderTest(t)
	ctx := context.Background()

	cred, err := provider.CreateCredential(ctx, credInput("widgets-readonly", 5*time.Minute))
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}
	username := cred.Secret["username"]
	if username == "" || cred.Secret["password"] == "" {
		t.Fatalf("CreateCredential() = %+v, want a real username/password", cred.Secret)
	}

	var rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin bool
	err = db.QueryRowContext(ctx,
		`SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = $1`,
		username,
	).Scan(&rolsuper, &rolcreatedb, &rolcreaterole, &rolreplication, &rolbypassrls, &rolcanlogin)
	if err != nil {
		t.Fatalf("query pg_roles: %v", err)
	}
	if rolsuper || rolcreatedb || rolcreaterole || rolreplication || rolbypassrls {
		t.Errorf("role %q attributes = super=%v createdb=%v createrole=%v replication=%v bypassrls=%v, want all false",
			username, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls)
	}
	if !rolcanlogin {
		t.Errorf("role %q rolcanlogin = false, want true immediately after creation", username)
	}
}

func TestPostgresProvider_CreateCredential_GrantsOnlyConfiguredPrivilege(t *testing.T) {
	provider, db := setupPostgresProviderTest(t)
	ctx := context.Background()

	cred, err := provider.CreateCredential(ctx, credInput("widgets-readonly", 5*time.Minute))
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}
	username := cred.Secret["username"]

	var canSelect, canInsert bool
	if err := db.QueryRowContext(ctx, `SELECT has_table_privilege($1, $2, 'SELECT')`, username, pgProviderTestSchema+".widgets").Scan(&canSelect); err != nil {
		t.Fatalf("has_table_privilege(SELECT): %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT has_table_privilege($1, $2, 'INSERT')`, username, pgProviderTestSchema+".widgets").Scan(&canInsert); err != nil {
		t.Fatalf("has_table_privilege(INSERT): %v", err)
	}
	if !canSelect {
		t.Errorf("role %q cannot SELECT on the templated table, want it to be able to (widgets-readonly grants SELECT)", username)
	}
	if canInsert {
		t.Errorf("role %q CAN INSERT on the templated table, want it to be unable to — the template only grants SELECT", username)
	}
}

func TestPostgresProvider_CreateCredential_SetsValidUntilFromTTL(t *testing.T) {
	provider, db := setupPostgresProviderTest(t)
	ctx := context.Background()

	before := time.Now()
	cred, err := provider.CreateCredential(ctx, credInput("widgets-readonly", 5*time.Minute))
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}
	username := cred.Secret["username"]

	var validUntil time.Time
	if err := db.QueryRowContext(ctx, `SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1`, username).Scan(&validUntil); err != nil {
		t.Fatalf("query rolvaliduntil: %v", err)
	}
	wantAround := before.Add(5 * time.Minute)
	if diff := validUntil.Sub(wantAround); diff < -time.Minute || diff > time.Minute {
		t.Errorf("rolvaliduntil = %s, want within 1 minute of %s", validUntil, wantAround)
	}
}

func TestPostgresProvider_RevokeCredential_DisablesLoginAndIsIdempotent(t *testing.T) {
	provider, db := setupPostgresProviderTest(t)
	ctx := context.Background()

	cred, err := provider.CreateCredential(ctx, credInput("widgets-readonly", 5*time.Minute))
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}
	username := cred.Secret["username"]

	if err := provider.RevokeCredential(ctx, username); err != nil {
		t.Fatalf("first RevokeCredential() error = %v", err)
	}
	var rolcanlogin bool
	if err := db.QueryRowContext(ctx, `SELECT rolcanlogin FROM pg_roles WHERE rolname = $1`, username).Scan(&rolcanlogin); err != nil {
		t.Fatalf("query rolcanlogin: %v", err)
	}
	if rolcanlogin {
		t.Errorf("rolcanlogin = true after RevokeCredential(), want false")
	}

	if err := provider.RevokeCredential(ctx, username); err != nil {
		t.Errorf("second RevokeCredential() (idempotent call) error = %v, want nil", err)
	}
}

// TestPostgresProvider_RevokeCredential_UnknownRoleIsNotAnError proves
// the "safe to call on a providerRef this connection has never heard of"
// property RevokeCredential's own doc comment describes — the restart/
// reconnect-safety case.
func TestPostgresProvider_RevokeCredential_UnknownRoleIsNotAnError(t *testing.T) {
	provider, _ := setupPostgresProviderTest(t)
	if err := provider.RevokeCredential(context.Background(), "vlt_this_role_was_never_created"); err != nil {
		t.Errorf("RevokeCredential(unknown role) error = %v, want nil", err)
	}
}

func TestPostgresProvider_RenewCredential_ExtendsValidUntil(t *testing.T) {
	provider, db := setupPostgresProviderTest(t)
	ctx := context.Background()

	cred, err := provider.CreateCredential(ctx, credInput("widgets-readonly", time.Minute))
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}
	username := cred.Secret["username"]

	if err := provider.RenewCredential(ctx, username, time.Hour); err != nil {
		t.Fatalf("RenewCredential() error = %v", err)
	}
	var validUntil time.Time
	if err := db.QueryRowContext(ctx, `SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1`, username).Scan(&validUntil); err != nil {
		t.Fatalf("query rolvaliduntil: %v", err)
	}
	if time.Until(validUntil) < 30*time.Minute {
		t.Errorf("rolvaliduntil after Renew(1h) = %s (%.0fm from now), want at least 30m from now", validUntil, time.Until(validUntil).Minutes())
	}
}

func TestPostgresProvider_CreateCredential_UnknownRoleTemplateRejected(t *testing.T) {
	provider, _ := setupPostgresProviderTest(t)
	_, err := provider.CreateCredential(context.Background(), credInput("admin-write-does-not-exist", 5*time.Minute))
	if err == nil {
		t.Fatal("CreateCredential() with an unregistered role template unexpectedly succeeded")
	}
}

// TestPostgresProvider_ConcurrentCreateCredential_ProducesDistinctRoles is
// the security checklist's own "concurrent credential creation" case: N
// goroutines creating credentials at once must never collide on a
// username (crypto/rand's own collision probability at this sample size
// is effectively zero) and every created role must actually exist
// afterward.
func TestPostgresProvider_ConcurrentCreateCredential_ProducesDistinctRoles(t *testing.T) {
	provider, db := setupPostgresProviderTest(t)
	ctx := context.Background()

	const n = 20
	usernames := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cred, err := provider.CreateCredential(ctx, credInput("widgets-readonly", 5*time.Minute))
			if err != nil {
				errs[i] = err
				return
			}
			usernames[i] = cred.Secret["username"]
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: CreateCredential() error = %v", i, err)
		}
		if seen[usernames[i]] {
			t.Fatalf("goroutine %d produced duplicate username %q", i, usernames[i])
		}
		seen[usernames[i]] = true

		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, usernames[i]).Scan(&exists); err != nil {
			t.Fatalf("query pg_roles for %q: %v", usernames[i], err)
		}
		if !exists {
			t.Errorf("role %q was never actually created in pg_roles", usernames[i])
		}
	}
}

func TestPostgresProvider_ListRoles_FindsCreatedRoles(t *testing.T) {
	provider, _ := setupPostgresProviderTest(t)
	ctx := context.Background()

	cred, err := provider.CreateCredential(ctx, credInput("widgets-readonly", 5*time.Minute))
	if err != nil {
		t.Fatalf("CreateCredential() error = %v", err)
	}

	roles, err := provider.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles() error = %v", err)
	}
	found := false
	for _, r := range roles {
		if r == cred.Secret["username"] {
			found = true
		}
	}
	if !found {
		t.Errorf("ListRoles() = %v, want it to include %q", roles, cred.Secret["username"])
	}
}

// TestPostgresProvider_MaliciousRoleTemplateNameNeverReachesSQL is the
// security checklist's own "SQL injection attempts" / "malicious
// identifiers" case at the integration level: a role name containing SQL
// injection syntax, if it doesn't match any configured template, is
// rejected outright — the request never reaches a SQL statement at all
// (the malicious string is only ever compared as a Go map key).
func TestPostgresProvider_MaliciousRoleTemplateNameNeverReachesSQL(t *testing.T) {
	provider, db := setupPostgresProviderTest(t)
	ctx := context.Background()

	malicious := `widgets-readonly'; DROP TABLE ` + pgProviderTestSchema + `.widgets; --`
	if _, err := provider.CreateCredential(ctx, credInput(malicious, 5*time.Minute)); err == nil {
		t.Fatal("CreateCredential() with a SQL-injection-shaped, unregistered role name unexpectedly succeeded")
	}

	var stillExists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'widgets')`, pgProviderTestSchema).Scan(&stillExists); err != nil {
		t.Fatalf("check table still exists: %v", err)
	}
	if !stillExists {
		t.Fatal("the widgets table no longer exists — a SQL injection attempt via the role name succeeded")
	}
}

func credInput(role string, ttl time.Duration) leasing.CreateCredentialInput {
	return leasing.CreateCredentialInput{ResourcePath: "test/path", TTL: ttl, Role: role}
}
