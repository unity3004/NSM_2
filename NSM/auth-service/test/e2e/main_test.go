//go:build e2e

package e2e

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

// TestMain loads test/fixtures/*.sql (the organizations row every test in
// this package needs via users.organization_id's FK) once per test-binary
// run, before any test executes — the same convention
// test/integration/main_test.go already established, duplicated here
// rather than shared across packages for the same reason
// generateTestEd25519PrivateKeyPEM-style helpers are already duplicated
// per test file throughout this codebase: it's a dozen lines, package
// boundaries in test/ don't share code today, and a shared package solely
// for this would be more machinery than the problem needs.
//
// When DATABASE_URL isn't set, this is a no-op: every test in this
// package calls its own skip-guard (see harness_test.go's newE2EServer)
// for the same reason.
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
		fmt.Fprintf(os.Stderr, "e2e TestMain: connect to %s: %v\n", dsn, err)
		os.Exit(1)
	}
	fixtureErr := loadFixtures(ctx, db)
	db.Close()
	if fixtureErr != nil {
		fmt.Fprintf(os.Stderr, "e2e TestMain: load fixtures: %v\n", fixtureErr)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

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
