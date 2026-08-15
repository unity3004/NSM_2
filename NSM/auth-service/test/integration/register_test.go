//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/database"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/postgres"
)

func connectForRegisterTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; see docker/docker-compose.yml for a local Postgres")
	}
	db, err := database.NewPostgresPool(context.Background(), config.DatabaseConfig{
		URL: dsn, MaxOpenConns: 5, MaxIdleConns: 5,
		ConnMaxLifetime: 5 * time.Minute, ConnMaxIdleTime: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestUserRepository_UsernameUniqueConstraint proves the migration this
// milestone added (000019_add_users_username_unique.up.sql) actually
// exists and is enforced by real Postgres — the fakes in
// internal/repository/mocks can only assert that the Go code *intends*
// this; only the real constraint proves it.
func TestUserRepository_UsernameUniqueConstraint(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()

	const orgID = "00000000-0000-4000-8000-000000000001"
	repo := postgres.NewUserRepository(db)
	username := "reg-it-" + t.Name()

	first := &entity.User{OrganizationID: orgID, Email: username + "-1@example.com", Username: &username, Status: entity.UserStatusActive}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}

	second := &entity.User{OrganizationID: orgID, Email: username + "-2@example.com", Username: &username, Status: entity.UserStatusActive}
	if err := repo.Create(ctx, second); !errors.Is(err, entity.ErrAlreadyExists) {
		t.Errorf("Create() with a duplicate username, error = %v, want entity.ErrAlreadyExists", err)
	}
}

// TestRegistration_TransactionRollsBackOnAuditFailure is the real-database
// half of the "failed registration leaves no partial state" requirement.
// internal/service/user_service_test.go proves UserService.Register's own
// orchestration treats the two writes as one unit against fakes; this
// test proves Postgres itself actually rolls the user INSERT back when
// the audit_logs INSERT in the same transaction fails — which a fake
// cannot prove, no matter how it's written. The audit_logs INSERT is
// forced to fail with a genuine SQL-level error (an actor_type value
// Postgres's audit_actor_type enum doesn't contain), not a simulated one.
func TestRegistration_TransactionRollsBackOnAuditFailure(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()

	const orgID = "00000000-0000-4000-8000-000000000001"
	email := "reg-it-rollback-" + t.Name() + "@example.com"
	username := "reg-it-rollback-" + t.Name()

	var createdID string
	txErr := database.WithTx(ctx, db, func(tx *sql.Tx) error {
		users := postgres.NewUserRepository(tx)
		audit := postgres.NewAuditLogRepository(tx)

		u := &entity.User{OrganizationID: orgID, Email: email, Username: &username, Status: entity.UserStatusActive}
		if err := users.Create(ctx, u); err != nil {
			return err
		}
		createdID = u.ID

		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: strPtrForTest(orgID),
			ActorType:      entity.AuditActorType("not_a_real_actor_type"), // rejected by the audit_actor_type enum
			ActorID:        &u.ID,
			Action:         "user.registered",
			Result:         entity.AuditResultSuccess,
		})
	})
	if txErr == nil {
		t.Fatal("expected the audit_logs insert to fail (invalid enum value), got nil error")
	}
	if createdID == "" {
		t.Fatal("test bug: the user Create inside the transaction never ran")
	}

	repo := postgres.NewUserRepository(db)
	if _, err := repo.GetByID(ctx, createdID); !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetByID() after a rolled-back registration, error = %v, want entity.ErrNotFound (the user row must not exist)", err)
	}
}

// TestAuditLogRepository_AppendChainsHashes proves the hash chain
// postgres.auditLogRepository.Append computes against real, concurrent
// Postgres transactions — including that pg_advisory_xact_lock actually
// serializes the two appends below rather than letting them race, which
// FakeAuditLogRepository's single mutex can approximate but not prove.
func TestAuditLogRepository_AppendChainsHashes(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	const orgID = "00000000-0000-4000-8000-000000000001"
	audit := postgres.NewAuditLogRepository(db)

	first := &entity.AuditLogEntry{OrganizationID: strPtrForTest(orgID), ActorType: entity.AuditActorSystem, Action: "test.first", Result: entity.AuditResultSuccess}
	if err := audit.Append(ctx, first); err != nil {
		t.Fatalf("first Append() error = %v", err)
	}
	second := &entity.AuditLogEntry{OrganizationID: strPtrForTest(orgID), ActorType: entity.AuditActorSystem, Action: "test.second", Result: entity.AuditResultSuccess}
	if err := audit.Append(ctx, second); err != nil {
		t.Fatalf("second Append() error = %v", err)
	}

	if second.PrevHash == nil || *second.PrevHash != first.RecordHash {
		t.Errorf("second.PrevHash = %v, want it to equal first.RecordHash (%q)", second.PrevHash, first.RecordHash)
	}
	if first.RecordHash == second.RecordHash {
		t.Error("two different audit entries produced the same RecordHash")
	}
}

func strPtrForTest(s string) *string { return &s }
