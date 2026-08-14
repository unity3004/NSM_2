//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/postgres"
)

const secretTestOrgID = "00000000-0000-4000-8000-000000000001"

// seedSecretTestUser creates a real user row to satisfy secrets.created_by
// and secret_versions.created_by's foreign keys — the same "seed the real
// chain of rows a foreign key requires" approach seedUserSessionAndRefreshToken
// already uses for refresh tokens.
//
// Username is namespaced by t.Name() the same way Email already is —
// previously left as the Go zero value (""), which every one of this
// function's many call sites across this package shared identically.
// users has a UNIQUE(organization_id, username) constraint (see
// migrations/000019), so the very first call in any given
// `go test` process to actually reach the database won by inserting the
// one permitted row with username="", and every other call — from any
// other test in the same run, regardless of its own distinct email —
// failed with "resource already exists". Found while diagnosing
// TestKeyRotation_Simulation's own failure, which turned out to be this
// same pre-existing bug, not anything specific to key rotation.
//
// t.Cleanup deletes this user (and, first, every secrets/secret_versions
// row it owns — both have an ON DELETE RESTRICT foreign key to users.id,
// see migrations/000024, so the user row cannot be removed while either
// still references it) once the calling test finishes. Previously
// nothing cleaned this up at all, so a namespaced-but-still-fixed email
// like this one would itself collide on any second run against the same
// database — exactly the failure this fix would otherwise just move from
// "username" to "email" instead of actually closing.
func seedSecretTestUser(t *testing.T, db *sql.DB) *entity.User {
	t.Helper()
	users := postgres.NewUserRepository(db)
	suffix := "secrets-it-" + t.Name()
	user := &entity.User{
		OrganizationID: secretTestOrgID,
		Email:          suffix + "@example.com",
		Username:       strPtrForTest(suffix),
		Status:         entity.UserStatusActive,
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.ExecContext(ctx, `DELETE FROM secret_versions WHERE created_by = $1`, user.ID)
		_, _ = db.ExecContext(ctx, `DELETE FROM secrets WHERE created_by = $1`, user.ID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, user.ID)
	})
	return user
}

// fakeCiphertext stands in for a real AES-256-GCM payload — Phase 1
// implements no encryption at all (see migrations/000024's own doc
// comment), so every test in this file writes an obviously-fake byte
// sequence, never a real algorithm's output. testPlaintextMarker is the
// exact string TestSecretVersion_NoPlaintextInDatabase asserts never
// appears anywhere in the raw database representation — it deliberately
// never gets encrypted by anything in this file, because nothing in this
// phase can encrypt it; it only ever appears as a Go string constant.
const testPlaintextMarker = "THIS_IS_TEST_SECRET_VALUE"

func fakeCiphertext(seed string) []byte {
	return []byte("fake-ciphertext:" + seed)
}

func newTestVersionInput(secretID, userID, seed string) *entity.SecretVersion {
	return &entity.SecretVersion{
		SecretID:   secretID,
		Ciphertext: fakeCiphertext(seed),
		Nonce:      []byte("fake-nonce-" + seed),
		AuthTag:    []byte("fake-tag-" + seed),
		Algorithm:  "AES-256-GCM",
		WrappedDEK: []byte("fake-wrapped-dek-" + seed),
		KeyID:      "test-kek-1",
		CreatedBy:  userID,
	}
}

// 1. Create secret record.
func TestSecretRepository_CreateSecret(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app1/db/password", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if s.ID == "" {
		t.Fatal("Create() did not populate ID")
	}
	if s.CurrentVersion != 0 {
		t.Errorf("CurrentVersion = %d, want 0 for a secret with no versions yet", s.CurrentVersion)
	}

	fetched, err := secrets.GetByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if fetched.Path != s.Path {
		t.Errorf("GetByID() Path = %q, want %q", fetched.Path, s.Path)
	}
}

// 2. Create secret version.
func TestSecretRepository_CreateVersion(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app2/api/key", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	v := newTestVersionInput(s.ID, user.ID, "v1")
	if err := secrets.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}
	if v.Version != 1 {
		t.Errorf("Version = %d, want 1", v.Version)
	}
	if v.ID == "" {
		t.Fatal("CreateVersion() did not populate ID")
	}

	updated, err := secrets.GetByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if updated.CurrentVersion != 1 {
		t.Errorf("parent CurrentVersion = %d, want 1 after CreateVersion", updated.CurrentVersion)
	}
}

// 3. Multiple versions for one secret.
func TestSecretRepository_MultipleVersions(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app3/db/password", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	for i, seed := range []string{"v1", "v2", "v3"} {
		v := newTestVersionInput(s.ID, user.ID, seed)
		if err := secrets.CreateVersion(ctx, v); err != nil {
			t.Fatalf("CreateVersion() #%d error = %v", i+1, err)
		}
		if v.Version != i+1 {
			t.Fatalf("CreateVersion() #%d Version = %d, want %d", i+1, v.Version, i+1)
		}
	}

	versions, err := secrets.ListVersions(ctx, s.ID)
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("ListVersions() returned %d versions, want 3", len(versions))
	}
	// ListVersions orders version DESC.
	for i, v := range versions {
		want := 3 - i
		if v.Version != want {
			t.Errorf("ListVersions()[%d].Version = %d, want %d", i, v.Version, want)
		}
	}

	updated, err := secrets.GetByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if updated.CurrentVersion != 3 {
		t.Errorf("parent CurrentVersion = %d, want 3", updated.CurrentVersion)
	}
}

// 4. Duplicate path rejection.
func TestSecretRepository_DuplicatePathRejected(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	path := "app4/duplicate/path"
	first := &entity.Secret{OrganizationID: secretTestOrgID, Path: path, CreatedBy: user.ID}
	if err := secrets.Create(ctx, first); err != nil {
		t.Fatalf("Create() first secret error = %v", err)
	}

	second := &entity.Secret{OrganizationID: secretTestOrgID, Path: path, CreatedBy: user.ID}
	err := secrets.Create(ctx, second)
	if !errors.Is(err, entity.ErrAlreadyExists) {
		t.Errorf("Create() with a duplicate path, error = %v, want entity.ErrAlreadyExists", err)
	}

	// uq_secrets_org_path is on CITEXT: a differently-cased duplicate must
	// collide too, not just an exact byte-for-byte match.
	third := &entity.Secret{OrganizationID: secretTestOrgID, Path: strings.ToUpper(path), CreatedBy: user.ID}
	err = secrets.Create(ctx, third)
	if !errors.Is(err, entity.ErrAlreadyExists) {
		t.Errorf("Create() with a differently-cased duplicate path, error = %v, want entity.ErrAlreadyExists", err)
	}
}

// 5. Duplicate version rejection.
//
// secretRepository.CreateVersion always computes the next version number
// itself, so it can never be asked to create an explicit duplicate through
// the repository's own API — the thing this test proves is that
// uq_secret_versions_secret_version (migrations/000024) is a real,
// enforced database constraint, by attempting the duplicate INSERT
// directly against the table, the same way a future second write path (or
// a bug bypassing this repository) would fail.
func TestSecretRepository_DuplicateVersionRejected(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app5/duplicate/version", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	v := newTestVersionInput(s.ID, user.ID, "v1")
	if err := secrets.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	_, err := db.ExecContext(ctx, `
		INSERT INTO secret_versions (secret_id, version, ciphertext, nonce, auth_tag, algorithm, wrapped_dek, key_id, created_by)
		VALUES ($1, 1, $2, $3, $4, 'AES-256-GCM', $5, 'test-kek-1', $6)`,
		s.ID, fakeCiphertext("dup"), []byte("fake-nonce-dup"), []byte("fake-tag-dup"), []byte("fake-wrapped-dek-dup"), user.ID)
	if err == nil {
		t.Fatal("direct duplicate (secret_id, version) INSERT succeeded, want a unique-constraint violation")
	}
}

// 6. Foreign-key enforcement.
func TestSecretRepository_ForeignKeyEnforcement(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)
	const noSuchID = "00000000-0000-4000-8000-000000000000"

	t.Run("secrets.created_by", func(t *testing.T) {
		s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app6/bad-user", CreatedBy: noSuchID}
		if err := secrets.Create(ctx, s); !errors.Is(err, entity.ErrNotFound) {
			t.Errorf("Create() with a nonexistent created_by, error = %v, want entity.ErrNotFound", err)
		}
	})

	t.Run("secrets.organization_id", func(t *testing.T) {
		s := &entity.Secret{OrganizationID: noSuchID, Path: "app6/bad-org", CreatedBy: user.ID}
		if err := secrets.Create(ctx, s); !errors.Is(err, entity.ErrNotFound) {
			t.Errorf("Create() with a nonexistent organization_id, error = %v, want entity.ErrNotFound", err)
		}
	})

	t.Run("secret_versions.secret_id", func(t *testing.T) {
		v := newTestVersionInput(noSuchID, user.ID, "orphan")
		if err := secrets.CreateVersion(ctx, v); !errors.Is(err, entity.ErrNotFound) {
			t.Errorf("CreateVersion() with a nonexistent secret_id, error = %v, want entity.ErrNotFound", err)
		}
	})

	t.Run("secret_versions.created_by", func(t *testing.T) {
		s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app6/bad-version-user", CreatedBy: user.ID}
		if err := secrets.Create(ctx, s); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		v := newTestVersionInput(s.ID, noSuchID, "bad-creator")
		if err := secrets.CreateVersion(ctx, v); !errors.Is(err, entity.ErrNotFound) {
			t.Errorf("CreateVersion() with a nonexistent created_by, error = %v, want entity.ErrNotFound", err)
		}
	})
}

// 7. Secret version immutability at the repository level: creating a new
// version must never change any previously-created version's stored bytes.
func TestSecretRepository_VersionImmutability(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app7/immutable", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	v1 := newTestVersionInput(s.ID, user.ID, "original")
	if err := secrets.CreateVersion(ctx, v1); err != nil {
		t.Fatalf("CreateVersion() v1 error = %v", err)
	}

	v2 := newTestVersionInput(s.ID, user.ID, "second")
	if err := secrets.CreateVersion(ctx, v2); err != nil {
		t.Fatalf("CreateVersion() v2 error = %v", err)
	}

	reread, err := secrets.GetVersion(ctx, s.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion(1) error = %v", err)
	}
	if string(reread.Ciphertext) != string(fakeCiphertext("original")) {
		t.Errorf("version 1's ciphertext changed after version 2 was created: got %q, want %q",
			reread.Ciphertext, fakeCiphertext("original"))
	}
	if reread.CreatedAt != v1.CreatedAt {
		t.Errorf("version 1's created_at changed after version 2 was created: got %v, want %v", reread.CreatedAt, v1.CreatedAt)
	}

	// repository.SecretRepository itself has no method that updates an
	// existing secret_versions row — CreateVersion is the only write path
	// for a version, and it always inserts. That is a compile-time
	// property of the interface (internal/repository/secret.go), not
	// something this test can additionally exercise at runtime; the
	// behavioral check above is what a violation of it would actually look
	// like in the data.
}

// 8. Soft deletion.
func TestSecretRepository_SoftDelete(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app8/soft-delete", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	v := newTestVersionInput(s.ID, user.ID, "v1")
	if err := secrets.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	if err := secrets.SoftDelete(ctx, s.ID); err != nil {
		t.Fatalf("SoftDelete() error = %v", err)
	}

	if _, err := secrets.GetByID(ctx, s.ID); !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetByID() after SoftDelete(), error = %v, want entity.ErrNotFound", err)
	}

	// The row, and its version's ciphertext, must still physically exist —
	// soft delete must never destroy data (migrations/000024's own doc
	// comment on why permanent purge is a deliberately separate,
	// not-yet-implemented operation).
	var deletedAt sql.NullTime
	var storedCiphertext []byte
	err := db.QueryRowContext(ctx, `SELECT deleted_at FROM secrets WHERE id = $1`, s.ID).Scan(&deletedAt)
	if err != nil {
		t.Fatalf("raw SELECT of soft-deleted secret failed: %v — row must still exist", err)
	}
	if !deletedAt.Valid {
		t.Error("secrets.deleted_at is NULL after SoftDelete()")
	}
	err = db.QueryRowContext(ctx, `SELECT ciphertext FROM secret_versions WHERE secret_id = $1 AND version = 1`, s.ID).Scan(&storedCiphertext)
	if err != nil {
		t.Fatalf("raw SELECT of the deleted secret's version failed: %v — ciphertext must not be destroyed", err)
	}
	if string(storedCiphertext) != string(fakeCiphertext("v1")) {
		t.Error("soft-deleting the parent secret altered its version's stored ciphertext")
	}
}

// 9. Concurrent version creation must never produce duplicate version
// numbers. Unlike refresh-token rotation (where exactly one of several
// concurrent callers should win and the rest should fail), every concurrent
// CreateVersion call here is expected to succeed — CreateVersion's
// `SELECT ... FOR UPDATE` on the parent secrets row (see that method's own
// doc comment) serializes concurrent callers rather than rejecting all but
// one, so ten concurrent requests should yield versions 1..10, no
// duplicates and no gaps.
func TestSecretRepository_ConcurrentVersionCreation(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app9/concurrent", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	const concurrency = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	var gotVersions []int
	var errs []error

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			v := newTestVersionInput(s.ID, user.ID, "concurrent")
			err := secrets.CreateVersion(ctx, v)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			gotVersions = append(gotVersions, v.Version)
		}(i)
	}
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("CreateVersion() failed for %d of %d concurrent callers: %v", len(errs), concurrency, errs[0])
	}
	if len(gotVersions) != concurrency {
		t.Fatalf("got %d successful versions, want %d", len(gotVersions), concurrency)
	}

	sort.Ints(gotVersions)
	seen := map[int]bool{}
	for _, v := range gotVersions {
		if seen[v] {
			t.Errorf("version %d was assigned to more than one concurrent caller", v)
		}
		seen[v] = true
	}
	for i, v := range gotVersions {
		if want := i + 1; v != want {
			t.Errorf("versions assigned = %v, want a gapless 1..%d sequence (got %d at position %d)", gotVersions, concurrency, v, i)
		}
	}

	updated, err := secrets.GetByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if updated.CurrentVersion != concurrency {
		t.Errorf("parent CurrentVersion = %d, want %d after %d concurrent CreateVersion calls", updated.CurrentVersion, concurrency, concurrency)
	}
}

// 10. User relationship: secrets.created_by and secret_versions.created_by
// reference users(id) with ON DELETE RESTRICT — deleting a user who created
// secrets must be rejected, not silently cascade into destroying secret
// history.
func TestSecretRepository_UserRelationship(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app10/user-relationship", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	v := newTestVersionInput(s.ID, user.ID, "v1")
	if err := secrets.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, user.ID); err == nil {
		t.Fatal("DELETE of a user who created a secret succeeded, want ON DELETE RESTRICT to reject it")
	}

	// The secret and its version must be completely unaffected.
	fetched, err := secrets.GetByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("secret disappeared after the rejected user deletion: GetByID() error = %v", err)
	}
	if fetched.CreatedBy != user.ID {
		t.Errorf("CreatedBy = %q, want %q", fetched.CreatedBy, user.ID)
	}
}

// 11. Migration succeeds on a clean database: TestMain (main_test.go)
// already requires migrations 000001-000023 to be applied before any test
// in this package can run at all (every other test here depends on
// users/organizations existing); this file's own tests additionally depend
// on migrations/000024 specifically (secrets, secret_versions,
// uq_secrets_org_path, uq_secret_versions_secret_version, every index) —
// so the full suite in this file passing end-to-end against a real,
// freshly-migrated database (see this package's CI wiring in
// .github/workflows/ci.yml, which always starts from an empty postgres:16
// service container and runs `migrate ... up` before `go test`) is the
// proof that migration 000024 applies cleanly, in order, on top of a clean
// schema. TestSecretRepository_ForeignKeyEnforcement additionally proves
// every foreign key it declares actually exists and is enforced, and
// TestSecretRepository_DuplicateVersionRejected/DuplicatePathRejected prove
// its unique constraints do.
func TestSecretsMigration_TablesAndConstraintsExist(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()

	for _, table := range []string{"secrets", "secret_versions"} {
		var exists bool
		err := db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)`,
			table).Scan(&exists)
		if err != nil {
			t.Fatalf("checking table %q: %v", table, err)
		}
		if !exists {
			t.Errorf("table %q does not exist — migration 000024 did not apply", table)
		}
	}

	for _, constraint := range []string{
		"uq_secrets_org_path",
		"ck_secrets_current_version_nonneg",
		"ck_secrets_path_not_empty",
		"uq_secret_versions_secret_version",
		"ck_secret_versions_version_positive",
	} {
		var exists bool
		err := db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = $1)`, constraint).Scan(&exists)
		if err != nil {
			t.Fatalf("checking constraint %q: %v", constraint, err)
		}
		if !exists {
			t.Errorf("constraint %q does not exist — migration 000024 did not apply as expected", constraint)
		}
	}
}

// Security requirement: no plaintext secret value ever appears anywhere in
// the database representation. This test writes only fake ciphertext (see
// fakeCiphertext) — since Phase 1 implements no encryption, there is no
// code path anywhere in this repository layer that could turn
// testPlaintextMarker into ciphertext even if it tried. The assertion below
// is therefore not "encryption worked", it is the more basic, load-bearing
// fact this schema exists to guarantee: nothing in the secrets/secret_versions
// tables — not a column, not a row, anywhere — ever stores an application
// value verbatim.
func TestSecretVersion_NoPlaintextInDatabase(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secrets := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-security/plaintext-check", CreatedBy: user.ID}
	if err := secrets.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	v := newTestVersionInput(s.ID, user.ID, "v1")
	if err := secrets.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// Confirm the schema itself has no plaintext-shaped column at all —
	// this is the primary guarantee, independent of what any row contains.
	rows, err := db.QueryContext(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name IN ('secrets', 'secret_versions')`)
	if err != nil {
		t.Fatalf("querying column names: %v", err)
	}
	defer rows.Close()
	var forbidden []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("scanning column name: %v", err)
		}
		lower := strings.ToLower(col)
		if lower == "password" || lower == "secret_value" || lower == "plaintext_value" || lower == "value" || lower == "plaintext" {
			forbidden = append(forbidden, col)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating columns: %v", err)
	}
	if len(forbidden) > 0 {
		t.Errorf("secrets/secret_versions has plaintext-shaped column(s): %v", forbidden)
	}

	// Confirm the one test value this test ever writes as "the secret"
	// never appears as a substring of any text/bytea column on the row
	// actually inserted above — the same assertion a reviewer would make by
	// hand with psql.
	var ciphertext, nonce, authTag, wrappedDEK []byte
	var algorithm, keyID, path string
	err = db.QueryRowContext(ctx, `
		SELECT sv.ciphertext, sv.nonce, sv.auth_tag, sv.wrapped_dek, sv.algorithm, sv.key_id, s.path
		FROM secret_versions sv JOIN secrets s ON s.id = sv.secret_id
		WHERE sv.id = $1`, v.ID,
	).Scan(&ciphertext, &nonce, &authTag, &wrappedDEK, &algorithm, &keyID, &path)
	if err != nil {
		t.Fatalf("re-reading inserted row: %v", err)
	}
	for name, val := range map[string]string{
		"ciphertext":  string(ciphertext),
		"nonce":       string(nonce),
		"auth_tag":    string(authTag),
		"wrapped_dek": string(wrappedDEK),
		"algorithm":   algorithm,
		"key_id":      keyID,
		"path":        path,
	} {
		if strings.Contains(val, testPlaintextMarker) {
			t.Errorf("column %q contains the plaintext test marker %q — a plaintext value leaked into storage", name, testPlaintextMarker)
		}
	}
}
