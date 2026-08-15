//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/util"
)

// newTestLease builds an in-memory entity.Lease ready for Create — owner
// IDs are freshly generated UUIDs (owner_identity_id carries no foreign
// key in migrations/000031, since it may name either a users row or a
// service_accounts row — see that migration's own comment) so this file
// never needs to seed a real user/service account just to satisfy a
// leases-table constraint.
func newTestLease(resourcePath string) *entity.Lease {
	return &entity.Lease{
		OrganizationID:    secretTestOrgID,
		LeaseType:         "dev-credential",
		ResourcePath:      resourcePath,
		OwnerIdentityType: entity.LeaseOwnerUser,
		OwnerIdentityID:   util.NewUUID(),
		Status:            entity.LeaseStatusActive,
		Renewable:         true,
		TTL:               5 * time.Minute,
		MaxTTL:            time.Hour,
		ExpiresAt:         time.Now().Add(5 * time.Minute),
		Metadata:          map[string]any{"username": "dyn_abc123"},
	}
}

// TestLeaseRepository_CreateAndGet proves the full round trip through real
// Postgres — including the JSONB metadata column and the opaque
// provider_reference handle, never a credential value (see this file's
// own newTestLease doc comment).
func TestLeaseRepository_CreateAndGet(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	leases := postgres.NewLeaseRepository(db)

	l := newTestLease("database/prod/readonly")
	ref := "dyn_abc123"
	l.ProviderRef = &ref
	if err := leases.Create(ctx, l); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if l.ID == "" || l.CreatedAt.IsZero() {
		t.Fatal("Create() did not populate ID/CreatedAt")
	}

	fetched, err := leases.GetByID(ctx, l.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if fetched.ResourcePath != l.ResourcePath || fetched.Status != entity.LeaseStatusActive {
		t.Errorf("GetByID() = %+v, want a matching active lease", fetched)
	}
	if fetched.ProviderRef == nil || *fetched.ProviderRef != ref {
		t.Errorf("GetByID() ProviderRef = %v, want %q", fetched.ProviderRef, ref)
	}
	if fetched.Metadata["username"] != "dyn_abc123" {
		t.Errorf("GetByID() Metadata = %+v, want username=dyn_abc123", fetched.Metadata)
	}
	if fetched.TTL != 5*time.Minute {
		t.Errorf("GetByID() TTL = %s, want 5m (the ttl_seconds column round-tripped through time.Duration)", fetched.TTL)
	}
}

func TestLeaseRepository_GetByID_UnknownIDReturnsNotFound(t *testing.T) {
	db := connectForRegisterTest(t)
	leases := postgres.NewLeaseRepository(db)
	if _, err := leases.GetByID(context.Background(), util.NewUUID()); err != entity.ErrNotFound {
		t.Errorf("GetByID(unknown) error = %v, want entity.ErrNotFound", err)
	}
}

// TestLeaseRepository_List_FiltersByOwnerAndStatus proves
// LeaseFilter's OwnerIdentityID/Status fields actually narrow the query
// against real Postgres, not just the in-memory fake.
func TestLeaseRepository_List_FiltersByOwnerAndStatus(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	leases := postgres.NewLeaseRepository(db)

	mine := newTestLease("list-test/mine")
	if err := leases.Create(ctx, mine); err != nil {
		t.Fatalf("Create(mine): %v", err)
	}
	someoneElse := newTestLease("list-test/someone-else")
	if err := leases.Create(ctx, someoneElse); err != nil {
		t.Fatalf("Create(someoneElse): %v", err)
	}
	if _, err := leases.Revoke(ctx, mine.ID, nil, time.Now()); err != nil {
		t.Fatalf("Revoke(mine): %v", err)
	}

	ownerID := mine.OwnerIdentityID
	revokedStatus := entity.LeaseStatusRevoked
	found, err := leases.List(ctx, secretTestOrgID, repository.LeaseFilter{
		OwnerIdentityID: &ownerID, Status: &revokedStatus, Limit: 50,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(found) != 1 || found[0].ID != mine.ID {
		t.Errorf("List(owner=mine, status=revoked) = %+v, want exactly [mine]", found)
	}
}

// TestLeaseRepository_Renew_OnlyActiveLeasesTransition proves the
// database-level `WHERE status = 'active'` guard directly: renewing a
// revoked lease must fail entity.ErrNotFound (checkRowsAffected's own
// "zero rows affected" translation), never silently succeed.
func TestLeaseRepository_Renew_OnlyActiveLeasesTransition(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	leases := postgres.NewLeaseRepository(db)

	l := newTestLease("renew-test/active")
	if err := leases.Create(ctx, l); err != nil {
		t.Fatalf("Create(): %v", err)
	}
	newExpiry := time.Now().Add(10 * time.Minute)
	if err := leases.Renew(ctx, l.ID, 10*time.Minute, newExpiry); err != nil {
		t.Fatalf("Renew() on an active lease, error = %v", err)
	}
	fetched, err := leases.GetByID(ctx, l.ID)
	if err != nil {
		t.Fatalf("GetByID(): %v", err)
	}
	if fetched.TTL != 10*time.Minute {
		t.Errorf("TTL after Renew() = %s, want 10m", fetched.TTL)
	}

	if _, err := leases.Revoke(ctx, l.ID, nil, time.Now()); err != nil {
		t.Fatalf("Revoke(): %v", err)
	}
	if err := leases.Renew(ctx, l.ID, 10*time.Minute, time.Now().Add(10*time.Minute)); err != entity.ErrNotFound {
		t.Errorf("Renew() on a revoked lease, error = %v, want entity.ErrNotFound", err)
	}
}

// TestLeaseRepository_Revoke_IsIdempotentAtTheDatabaseLevel proves
// transitioned=false on a second revoke — the signal
// LeaseService.Revoke's own idempotency (never a second audit entry)
// depends on.
func TestLeaseRepository_Revoke_IsIdempotentAtTheDatabaseLevel(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	leases := postgres.NewLeaseRepository(db)

	l := newTestLease("revoke-test/idempotent")
	if err := leases.Create(ctx, l); err != nil {
		t.Fatalf("Create(): %v", err)
	}

	transitioned, err := leases.Revoke(ctx, l.ID, nil, time.Now())
	if err != nil || !transitioned {
		t.Fatalf("first Revoke() = (%v, %v), want (true, nil)", transitioned, err)
	}
	transitioned, err = leases.Revoke(ctx, l.ID, nil, time.Now())
	if err != nil || transitioned {
		t.Fatalf("second Revoke() = (%v, %v), want (false, nil)", transitioned, err)
	}
}

// TestLeaseRepository_ExpireOverdue_TransitionsOnlyOverdueActiveLeases is
// the database-level half of expiration enforcement's own proof: a lease
// already past its expires_at, still marked active, actually flips to
// expired and is returned by ExpireOverdue; a lease with time remaining
// does not.
func TestLeaseRepository_ExpireOverdue_TransitionsOnlyOverdueActiveLeases(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	leases := postgres.NewLeaseRepository(db)

	overdue := newTestLease("expire-test/overdue")
	overdue.ExpiresAt = time.Now().Add(-time.Hour)
	if err := leases.Create(ctx, overdue); err != nil {
		t.Fatalf("Create(overdue): %v", err)
	}
	notYet := newTestLease("expire-test/not-yet")
	notYet.ExpiresAt = time.Now().Add(time.Hour)
	if err := leases.Create(ctx, notYet); err != nil {
		t.Fatalf("Create(notYet): %v", err)
	}

	transitioned, err := leases.ExpireOverdue(ctx, time.Now())
	if err != nil {
		t.Fatalf("ExpireOverdue() error = %v", err)
	}
	ids := map[string]bool{}
	for _, l := range transitioned {
		ids[l.ID] = true
	}
	if !ids[overdue.ID] {
		t.Errorf("ExpireOverdue() did not transition the overdue lease %s", overdue.ID)
	}
	if ids[notYet.ID] {
		t.Errorf("ExpireOverdue() transitioned a not-yet-expired lease %s", notYet.ID)
	}

	fetched, err := leases.GetByID(ctx, overdue.ID)
	if err != nil {
		t.Fatalf("GetByID(overdue): %v", err)
	}
	if fetched.Status != entity.LeaseStatusExpired {
		t.Errorf("overdue lease Status after ExpireOverdue() = %q, want expired", fetched.Status)
	}
}

// TestLeaseRepository_SurvivesReconnect is the restart/recovery proof the
// security checklist calls for directly: a lease created against one
// *sql.DB connection is still present, with its lifecycle state intact,
// when read back through a brand-new connection pool — the same proof
// every other durable entity in this codebase gets by virtue of never
// living anywhere but Postgres, made explicit here because Sprint 5 Task
// 2's own objective calls out "lease state must survive restart" by name.
func TestLeaseRepository_SurvivesReconnect(t *testing.T) {
	db1 := connectForRegisterTest(t)
	l := newTestLease("restart-test/survives")
	if err := postgres.NewLeaseRepository(db1).Create(context.Background(), l); err != nil {
		t.Fatalf("Create(): %v", err)
	}

	// A second, independent connection pool — the closest a single-process
	// test binary can get to "the server restarted and reconnected,"
	// without actually restarting anything.
	db2 := connectForRegisterTest(t)
	fetched, err := postgres.NewLeaseRepository(db2).GetByID(context.Background(), l.ID)
	if err != nil {
		t.Fatalf("GetByID() over a fresh connection pool, error = %v", err)
	}
	if fetched.ID != l.ID || fetched.Status != entity.LeaseStatusActive {
		t.Errorf("GetByID() over a fresh connection pool = %+v, want the same active lease", fetched)
	}
}
