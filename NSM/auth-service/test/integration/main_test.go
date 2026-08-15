//go:build integration

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/database"
)

// TestMain applies this package's SQL fixtures — currently just
// test/fixtures/organizations.sql, the row every integration test's
// hardcoded organization ID depends on via users.organization_id's FK —
// exactly once per test binary run, before any test executes. Fixtures
// are test data, not schema, so they don't live in migrations/ (see that
// directory's own migrations), but they still have to land in the
// database somehow before the tests that assume they exist can run. Doing
// it here means every test in this package gets a migrated database with
// fixtures already loaded automatically, rather than each test file (or
// a developer running one test by hand) having to remember to load them.
//
// When DATABASE_URL isn't set, this is a no-op: every test in this
// package already calls its own connectForRegisterTest (or the
// equivalent inline check in user_repository_test.go) and skips itself
// for the same reason. TestMain doesn't duplicate that check by failing
// outright — it only tries to load fixtures at all if there's a database
// to load them into, so `go test -tags=integration ./test/integration/...`
// without DATABASE_URL set still runs (and skips) exactly as it does
// today.
func TestMain(m *testing.M) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		os.Exit(m.Run())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.NewPostgresPool(ctx, config.DatabaseConfig{
		URL:             dsn,
		MaxOpenConns:    2,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		ConnMaxIdleTime: time.Minute,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration TestMain: connect to %s: %v\n", os.Getenv("DATABASE_URL"), err)
		os.Exit(1)
	}
	fixtureErr := loadFixtures(ctx, db)
	db.Close()
	if fixtureErr != nil {
		fmt.Fprintf(os.Stderr, "integration TestMain: load fixtures: %v\n", fixtureErr)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// loadFixtures applies every *.sql file directly under test/fixtures, in
// lexical filename order, against an already-migrated database. Each
// fixture file is expected to be idempotent — organizations.sql's own
// `ON CONFLICT (id) DO NOTHING` is the existing example — so re-running
// the whole test binary against a database that already has fixtures
// loaded is exactly as safe as running it once against a freshly
// migrated one.
func loadFixtures(ctx context.Context, db *sql.DB) error {
	const dir = "../fixtures"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if _, err := db.ExecContext(ctx, string(contents)); err != nil {
			return fmt.Errorf("exec %s: %w", path, err)
		}
	}
	return nil
}
