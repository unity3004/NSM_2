//go:build integration

// The integration build tag keeps this file out of `go test ./...` in the
// normal unit-test run (see internal/service/auth_service_test.go, which
// needs no tag because it needs no database) — it only runs via
// `go test -tags=integration ./test/integration/...`, wired up in
// .github/workflows/ci.yml against a real, migrated Postgres. This is the
// layer that actually proves internal/repository/postgres's SQL is
// correct; the fakes in internal/repository/mocks prove internal/service's
// logic is correct assuming the SQL is — two different claims, two
// different test suites.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/database"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/postgres"
)

func TestUserRepository_CreateAndGetByEmail(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; see docker/docker-compose.yml for a local Postgres")
	}

	ctx := context.Background()
	// A bare DATABASE_URL (no AUTH_ prefix, no Viper) is deliberate here:
	// this test's job is to prove internal/repository/postgres's SQL is
	// correct against a real database, not to re-test internal/config's
	// loading — see config.DatabaseConfig.DSN for why URL wins outright.
	db, err := database.NewPostgresPool(ctx, config.DatabaseConfig{
		URL:             dsn,
		MaxOpenConns:    5,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()

	// This test assumes migrations have already been applied to DATABASE_URL
	// (see the "Run migrations" step in ci.yml) and that an organization
	// with this ID exists via a fixture — see test/fixtures/.
	const orgID = "00000000-0000-4000-8000-000000000001"

	repo := postgres.NewUserRepository(db)
	email := "integration-test-" + t.Name() + "@example.com"

	created := &entity.User{
		OrganizationID: orgID,
		Email:          email,
		Status:         entity.UserStatusActive,
	}
	if err := repo.Create(ctx, created); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.ID == "" {
		t.Fatal("Create() did not populate ID")
	}

	fetched, err := repo.GetByEmail(ctx, orgID, email)
	if err != nil {
		t.Fatalf("GetByEmail() error = %v", err)
	}
	if fetched.ID != created.ID {
		t.Errorf("GetByEmail() returned ID %q, want %q", fetched.ID, created.ID)
	}
}
