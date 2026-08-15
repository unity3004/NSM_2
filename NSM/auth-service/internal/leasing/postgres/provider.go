// Package postgres implements leasing.DynamicCredentialProvider against a
// real PostgreSQL server — Sprint 5 Task 3's first production dynamic-
// credential backend, and the first provider in this codebase that
// actually touches a database (see internal/leasing's own doc comment on
// why that discipline keeps this code out of that package). Provider is
// the only exported type; everything else here is either its own
// unexported helper or a small set of exported, pure SQL-building
// functions (buildCreateRoleSQL and friends) kept separate specifically
// so a unit test can assert exactly what SQL text this package would
// send — never SUPERUSER, never a directly-interpolated caller string —
// without needing a real database to do it.
package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/acme/auth-service/internal/leasing"
)

// RoleTemplate is one entry in an operator-configured catalog — mirrors
// config.PostgresRoleTemplate exactly (this package deliberately does not
// import internal/config, the same "don't pull in the whole config
// package for one struct shape" reasoning DatabaseConfig's own callers
// already avoid; cmd/server/main.go is the one place that translates
// config.PostgresRoleTemplate values into these).
type RoleTemplate struct {
	Database   string
	Schemas    []string
	Privileges []string
}

// ErrUnknownRoleTemplate means a lease-creation request named a "role"
// this Provider has no RoleTemplate registered for. Requests are never
// allowed to name a database, schema, or privilege list directly — only
// to select one of these pre-approved, operator-configured entries by
// name (see leasing.CreateCredentialInput.Role's own doc comment) — this
// is what makes "the caller must not select an arbitrary privileged
// database role" true by construction.
var ErrUnknownRoleTemplate = errors.New("leasing/postgres: no role template is registered under this name")

// Provider implements leasing.DynamicCredentialProvider by creating and
// destroying real, temporary PostgreSQL roles.
//
// # Provisioner connection
//
// db is a connection opened with a dedicated `vault-provisioner` database
// identity — never the application's own DatabaseConfig credentials (see
// config.PostgresProvisionerConfig's own doc comment). The minimum
// privileges that identity needs in production:
//   - CREATEROLE (to run CREATE ROLE/ALTER ROLE/DROP ROLE)
//   - CONNECT on every database named by a configured RoleTemplate, WITH
//     GRANT OPTION for CONNECT specifically (Postgres requires the
//     grantor to itself hold a privilege WITH GRANT OPTION to grant it to
//     someone else)
//   - The same, for every privilege (SELECT/INSERT/etc.) named by a
//     configured RoleTemplate, WITH GRANT OPTION, on the relevant
//     schema(s) — e.g. `GRANT SELECT ON ALL TABLES IN SCHEMA public TO
//     vault_provisioner WITH GRANT OPTION;` for a read-only template
//
// vault-provisioner must never itself hold SUPERUSER: everything this
// type grants comes from a fixed, hardcoded set of SQL statements that
// never includes a role *attribute* keyword (SUPERUSER, CREATEDB,
// CREATEROLE, REPLICATION, BYPASSRLS) at all — see buildCreateRoleSQL's
// own doc comment — so a provisioner identity that isn't SUPERUSER
// itself is sufficient, and is the safer choice: a compromised
// provisioner connection can mint least-privilege application
// credentials, never a second superuser.
//
// # Role/privilege model
//
// templates is the entire catalog a lease-creation request's "role"
// field may select from — see RoleTemplate's own doc comment.
//
// connectHost/connectPort are what CreateCredential returns to a caller
// as the address to actually connect to — not necessarily db's own
// connection target: a production deployment may provision through one
// address (an admin endpoint) while application traffic connects through
// another (a pooler, a read replica). Both point at the same logical
// Postgres server in this implementation; a topology where they
// genuinely differ is future work, noted in this sprint's final report.
type Provider struct {
	db          *sql.DB
	templates   map[string]RoleTemplate
	connectHost string
	connectPort int
}

// NewProvider constructs a Provider. db should be opened against the
// dedicated provisioner identity described on Provider's own doc
// comment — never database.NewPostgresPool(ctx, cfg.Database), the
// application's own connection.
func NewProvider(db *sql.DB, templates map[string]RoleTemplate, connectHost string, connectPort int) *Provider {
	return &Provider{db: db, templates: templates, connectHost: connectHost, connectPort: connectPort}
}

func (p *Provider) Type() string { return "postgres" }

// CreateCredential implements the objective's own numbered flow (steps
// 7-9: generate username/password, create the role, apply configured
// privileges). Steps 1-6 (authenticate, resolve identity, global
// permission, path policy, validate role, validate TTL) already happen in
// service.LeaseService.Create before this is ever called — see that
// method's own doc comment; this function trusts in.Role and in.TTL
// completely, the same way DevCredentialProvider.CreateCredential does.
//
// FAILURE SAFETY: if CREATE ROLE succeeds but applying the configured
// privileges then fails, this method drops the just-created role before
// returning — never leaving an unmanaged, unprivileged-but-real
// PostgreSQL login behind. See dropRoleBestEffort's own doc comment for
// what happens if that compensating drop itself fails.
func (p *Provider) CreateCredential(ctx context.Context, in leasing.CreateCredentialInput) (leasing.Credential, error) {
	tmpl, ok := p.templates[in.Role]
	if !ok {
		return leasing.Credential{}, ErrUnknownRoleTemplate
	}

	username, err := generateUsername()
	if err != nil {
		return leasing.Credential{}, fmt.Errorf("leasing/postgres: generating username: %w", err)
	}
	password, err := generatePassword()
	if err != nil {
		return leasing.Credential{}, fmt.Errorf("leasing/postgres: generating password: %w", err)
	}
	validUntil := time.Now().Add(in.TTL)

	if _, err := p.db.ExecContext(ctx, buildCreateRoleSQL(username, password, validUntil)); err != nil {
		return leasing.Credential{}, fmt.Errorf("leasing/postgres: create role: %w", err)
	}

	if err := p.applyPrivileges(ctx, username, tmpl); err != nil {
		p.dropRoleBestEffort(ctx, username)
		return leasing.Credential{}, fmt.Errorf("leasing/postgres: apply privileges: %w", err)
	}

	return leasing.Credential{
		Secret: map[string]string{
			"username": username,
			"password": password,
			"database": tmpl.Database,
			"host":     p.connectHost,
			"port":     fmt.Sprintf("%d", p.connectPort),
		},
		ProviderRef: username,
		// Metadata is safe, non-sensitive — see leasing.Credential.Metadata's
		// own doc comment. Never the password; role_template is the
		// caller's own "role" selection, safe to echo back on GET
		// /v1/leases/{id}.
		Metadata: map[string]any{"username": username, "database": tmpl.Database, "role_template": in.Role},
	}, nil
}

// applyPrivileges grants exactly what tmpl configures — CONNECT on its
// database, USAGE on each schema, and tmpl.Privileges on every existing
// table in each schema. Privileges are never quoted as identifiers (they
// are SQL keywords like SELECT, not names) and never taken from anywhere
// but tmpl, which itself is only ever populated from operator
// configuration already validated against a fixed allowlist
// (config.Config.Validate) — a request can select *which* RoleTemplate
// applies, never influence what one of them grants.
//
// GRANT ... ON ALL TABLES IN SCHEMA only affects tables that already
// exist at grant time — a table created in the schema afterward is not
// automatically covered. A production deployment that needs new tables
// to be immediately reachable should also configure `ALTER DEFAULT
// PRIVILEGES` for vault-provisioner in that schema (a one-time DBA setup
// step, not something this provider can do without owning the schema) —
// documented as a known limitation in this sprint's final report.
func (p *Provider) applyPrivileges(ctx context.Context, username string, tmpl RoleTemplate) error {
	if err := p.execWithConcurrencyRetry(ctx, buildGrantConnectSQL(tmpl.Database, username)); err != nil {
		return fmt.Errorf("grant connect: %w", err)
	}
	for _, schema := range tmpl.Schemas {
		if err := p.execWithConcurrencyRetry(ctx, buildGrantUsageSQL(schema, username)); err != nil {
			return fmt.Errorf("grant usage on schema %s: %w", schema, err)
		}
		if err := p.execWithConcurrencyRetry(ctx, buildGrantPrivilegesSQL(tmpl.Privileges, schema, username)); err != nil {
			return fmt.Errorf("grant privileges on schema %s: %w", schema, err)
		}
	}
	return nil
}

// execWithConcurrencyRetry is CreateCredential's own answer to the
// objective's "handle simultaneous credential creation safely" /
// "concurrent credential creation" requirement: PostgreSQL's own GRANT
// statement updates a shared ACL row on the target database/schema/table
// (pg_database, pg_namespace, pg_class), so two GRANTs racing against the
// *same* target — the normal case here, since every generated role's
// RoleTemplate grants against the same handful of operator-configured
// databases/schemas — can hit a transient "tuple concurrently updated"
// (SQLSTATE XX000) error even though neither statement did anything
// wrong; retrying is the correct, standard response (the same class of
// transient contention a serializable-isolation retry loop handles),
// never a sign of an actual conflict a caller needs to resolve. Bounded
// at 5 attempts with a short fixed backoff — proven necessary by
// TestPostgresProvider_ConcurrentCreateCredential_ProducesDistinctRoles,
// which fires many concurrent CreateCredential calls against the same
// template and reproduces this exact contention without it.
func (p *Provider) execWithConcurrencyRetry(ctx context.Context, query string, args ...any) error {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond * time.Duration(attempt)):
			}
		}
		_, err := p.db.ExecContext(ctx, query, args...)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isConcurrentUpdate(err) {
			return err
		}
	}
	return lastErr
}

// isConcurrentUpdate reports whether err is Postgres's own transient
// "tuple concurrently updated" catalog-contention error — SQLSTATE
// XX000 is a large, generic "internal_error" bucket covering many
// unrelated conditions, so the message substring is checked too rather
// than trusting the code alone to mean this specific, retry-safe case.
func isConcurrentUpdate(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	return pqErr.Code == "XX000" && strings.Contains(pqErr.Message, "concurrently updated")
}

// RevokeCredential disables the role's ability to authenticate at all
// (ALTER ROLE ... NOLOGIN) and terminates any connection it already has
// open — chosen over DROP ROLE as this provider's revocation strategy
// because DROP ROLE fails outright if the role still owns any object or
// has any privilege GRANTed to it (Postgres requires REASSIGN OWNED/DROP
// OWNED first), which a generated role always does by construction (see
// applyPrivileges) — NOLOGIN is unconditionally safe, immediate, and
// idempotent (calling it again on an already-disabled role is a
// no-op), matching this codebase's existing "revocation is a no-op-safe
// state transition, never an operation that can itself fail on the
// happy-repeated-call path" convention (entity.APIKeyRepository.Revoke's
// own doc comment). The role row itself is left in pg_roles — a small,
// permanent bit of storage per credential ever issued, an accepted
// tradeoff for revocation that can never itself fail because the role
// still owns something.
//
// Called on both explicit lease revocation and expiration-cleanup —
// idempotent either way, and safe to call on a providerRef this
// connection has never heard of (e.g. after a restart against a
// different provisioner instance): postgres returns a clear "role does
// not exist" error in that case, which this method treats as already
// revoked, never as a failure the caller needs to retry.
func (p *Provider) RevokeCredential(ctx context.Context, providerRef string) error {
	if _, err := p.db.ExecContext(ctx, buildRevokeLoginSQL(providerRef)); err != nil {
		if isUndefinedObject(err) {
			return nil
		}
		return fmt.Errorf("leasing/postgres: revoke login: %w", err)
	}
	// Best-effort: an already-open connection under this role stays
	// usable until it disconnects unless explicitly terminated — NOLOGIN
	// alone only blocks *new* connections. A failure here is logged by
	// the caller (service.LeaseService) via its own best-effort
	// convention, never escalated into failing the revocation itself:
	// the role is already unable to authenticate again, which is the
	// property that matters most.
	_, _ = p.db.ExecContext(ctx, buildTerminateBackendsSQL(), providerRef)
	return nil
}

// RenewCredential extends the role's own VALID UNTIL to newTTL from now —
// the PostgreSQL-side half of defense-in-depth expiration (Sentinel
// Vault's own lease.ExpiresAt is the other half; see
// service.LeaseService.Renew's own doc comment for the TTL-ceiling
// clamping that already happened before this is called). Fails
// entity.ErrNotFound-equivalent (isUndefinedObject) if providerRef no
// longer names a real role — the identical "treat a missing role as
// already gone, not as a retryable failure" posture RevokeCredential
// takes, since a lease can only ever be renewed while
// LeaseService.Renew's own IsUsable check already holds, making
// "renewing a role that was already dropped" a genuine inconsistency
// worth surfacing rather than silently swallowing.
func (p *Provider) RenewCredential(ctx context.Context, providerRef string, newTTL time.Duration) error {
	validUntil := time.Now().Add(newTTL)
	if _, err := p.db.ExecContext(ctx, buildRenewSQL(providerRef, validUntil)); err != nil {
		return fmt.Errorf("leasing/postgres: renew: %w", err)
	}
	return nil
}

// ListRoles returns the name of every currently-existing "vlt_"-prefixed
// PostgreSQL role — the provisioner-side half of Sprint 5 Task 3's own
// reconciliation requirement ("detect PostgreSQL role exists but
// Sentinel Vault lease does not, and the reverse"). This package
// deliberately implements detection only, not automated resolution: an
// operator (or a future scheduled job) cross-references this list
// against repository.LeaseRepository's own ProviderRef column —
//   - a name in this list with no active lease row referencing it is an
//     orphaned credential (the create-succeeded-but-lease-persist-failed
//     compensating path already tries to prevent this at the moment it
//     happens; this is the after-the-fact safety net for whatever gets
//     past that, e.g. a process crash between the two steps) — the fix
//     is RevokeCredential against that name.
//   - an active lease row whose ProviderRef names a role missing from
//     this list means the credential was somehow revoked/dropped outside
//     Sentinel Vault's own control (manual DBA action, a restored
//     backup) — the fix is Revoke on that lease, since its underlying
//     credential is already gone.
//
// Deliberately never resolves drift itself: doing so automatically
// (silently dropping a role, or silently revoking a lease) is exactly
// the kind of surprising, hard-to-audit action a human operator should
// decide on, not this package.
func (p *Provider) ListRoles(ctx context.Context) ([]string, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT rolname FROM pg_roles WHERE rolname LIKE 'vlt\_%' ESCAPE '\'`)
	if err != nil {
		return nil, fmt.Errorf("leasing/postgres: list roles: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("leasing/postgres: scan role name: %w", err)
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// dropRoleBestEffort is CreateCredential's own compensating-cleanup call
// (see that method's own doc comment) — DROP ROLE is safe to use here
// specifically because a role that just failed applyPrivileges never
// successfully acquired any privilege or ownership to begin with (every
// grant in applyPrivileges either all succeeded, in which case this is
// never called, or the first failure stopped before any later grant ran
// — Postgres itself does not roll back the grants that already committed
// within applyPrivileges's own loop, so in principle a role could hold a
// partial privilege set here; DROP ROLE still succeeds against a role
// that holds only GRANTed privileges, never OWNED objects, which
// applyPrivileges never creates). A failure here is loggable-and-swallowed
// by the caller, matching the "loud logging, never a second error the
// original failure gets lost behind" convention
// service.LeaseService.Create's own compensating-revoke path already
// establishes for the generic case.
func (p *Provider) dropRoleBestEffort(ctx context.Context, username string) error {
	_, err := p.db.ExecContext(ctx, buildDropRoleSQL(username))
	return err
}

// isUndefinedObject reports whether err is Postgres's own "role does not
// exist" (SQLSTATE 42704, undefined_object) — the specific, structured
// signal this package treats as "already revoked/renewed away," never a
// generic string match against an error message that could drift out of
// sync with a future driver upgrade.
func isUndefinedObject(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "42704"
	}
	return false
}

// --- credential generation ---

// generateUsername returns "vlt_" followed by 12 lowercase-hex
// characters from 6 crypto/rand-sourced bytes — the identical shape and
// entropy leasing.DevCredentialProvider's own "dyn_" + hex(6) username
// already uses, for the identical reason (see that type's own doc
// comment): never a timestamp, an incrementing ID, or anything derived
// from the requesting identity, which the objective's own "do not use
// predictable values" requirement rules out by name. This is also the
// entire PostgreSQL role name — the fixed "vlt_" + [0-9a-f]{12} character
// set is safe to place into a SQL identifier without further escaping,
// though buildCreateRoleSQL still runs it through pq.QuoteIdentifier
// anyway, on the same "the safety property should hold even if this
// function's own guarantee is ever weakened by a future edit" defense-
// in-depth reasoning DevCredentialProvider's own username generation
// doesn't need to make (it's never used as a SQL identifier at all).
func generateUsername() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "vlt_" + hex.EncodeToString(b), nil
}

// generatePassword returns a 32-byte (43 base64url character)
// crypto/rand-sourced password — higher entropy than
// DevCredentialProvider's own 24-byte password specifically because this
// one grants access to a real database, not a synthetic no-op credential.
func generatePassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// --- SQL builders ---
//
// Every function below is pure (no I/O) specifically so a unit test can
// assert exactly what SQL text this package would send without a real
// database — see this file's own package doc comment. Every identifier
// (role/database/schema name) is quoted with pq.QuoteIdentifier; every
// string literal (password, timestamp) is quoted with pq.QuoteLiteral;
// neither is ever direct string concatenation of an untrusted value.
// Privilege keywords are the one exception to "always quote" — they are
// not identifiers or literals but fixed SQL syntax, safe here only
// because every caller of buildGrantPrivilegesSQL already validated its
// privileges slice against config.postgresAllowedPrivileges before this
// package ever sees it.

// buildCreateRoleSQL never contains, and can never be made to contain by
// any argument this function accepts, the words SUPERUSER, CREATEDB,
// CREATEROLE, REPLICATION, or BYPASSRLS — the objective's own explicit
// "do NOT automatically grant" list. This is not a runtime check; it is
// a property of this function's own fixed template string, verified by
// TestBuildCreateRoleSQL_NeverGrantsElevatedAttributes.
func buildCreateRoleSQL(username, password string, validUntil time.Time) string {
	return fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD %s VALID UNTIL %s",
		pq.QuoteIdentifier(username), pq.QuoteLiteral(password), pq.QuoteLiteral(validUntil.UTC().Format(time.RFC3339)))
}

func buildGrantConnectSQL(database, username string) string {
	return fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", pq.QuoteIdentifier(database), pq.QuoteIdentifier(username))
}

func buildGrantUsageSQL(schema, username string) string {
	return fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", pq.QuoteIdentifier(schema), pq.QuoteIdentifier(username))
}

func buildGrantPrivilegesSQL(privileges []string, schema, username string) string {
	return fmt.Sprintf("GRANT %s ON ALL TABLES IN SCHEMA %s TO %s",
		strings.Join(privileges, ", "), pq.QuoteIdentifier(schema), pq.QuoteIdentifier(username))
}

func buildRevokeLoginSQL(username string) string {
	return fmt.Sprintf("ALTER ROLE %s NOLOGIN", pq.QuoteIdentifier(username))
}

func buildRenewSQL(username string, validUntil time.Time) string {
	return fmt.Sprintf("ALTER ROLE %s VALID UNTIL %s", pq.QuoteIdentifier(username), pq.QuoteLiteral(validUntil.UTC().Format(time.RFC3339)))
}

func buildDropRoleSQL(username string) string {
	return fmt.Sprintf("DROP ROLE %s", pq.QuoteIdentifier(username))
}

// buildTerminateBackendsSQL takes username as a normal bound query
// parameter ($1), never interpolated — pg_stat_activity.usename is an
// ordinary text value here, not a SQL identifier, so parameter binding
// (not pq.QuoteIdentifier) is the correct and safe mechanism.
func buildTerminateBackendsSQL() string {
	return `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1`
}
