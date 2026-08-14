package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/leasing"
	"github.com/acme/auth-service/internal/repository/mocks"
)

const (
	leaseTestOrgID    = "org-lease-1"
	leaseOwnerUserID  = "user-lease-owner-1"
	leaseOtherUserID  = "user-lease-other-1"
	leaseAdminID      = "user-lease-admin-1"
	leaseSAOwnerID    = "sa-payment-service"
	leaseFullRoleID   = "role-lease-full-access"
	leaseTestLeaseTyp = "dev-credential"
)

// testLeaseEnv is everything one test needs: a LeaseService plus direct
// access to the fakes underneath it, mirroring testSecretEnv/testSAEnv's
// own "fake the ports, exercise the real service logic" shape.
type testLeaseEnv struct {
	svc       *LeaseService
	leases    *mocks.FakeLeaseRepository
	rbac      *mocks.FakeRBACRepository
	users     *mocks.FakeUserRepository
	saRepo    *mocks.FakeServiceAccountRepository
	policies  *mocks.FakeSecretPolicyRepository
	policySvc *SecretPolicyService
	audit     *mocks.FakeAuditLogRepository
	provider  *leasing.DevCredentialProvider
}

// leaseTestConfig is the fixed TTL configuration every test in this file
// authorizes against — deliberately small numbers (minutes, not the
// production defaults) so TTL-clamping assertions stay readable.
func leaseTestConfig() (minTTL, defaultTTL, maxTTL, maxRenewableLifetime time.Duration) {
	return time.Minute, 10 * time.Minute, time.Hour, 2 * time.Hour
}

// newTestLeaseEnv wires a LeaseService against in-memory fakes and the
// real leasing.DevCredentialProvider (real crypto/rand credential
// generation, no external system) — leaseOwnerUserID and leaseSAOwnerID
// are pre-granted secrets:read, leases:create, leases:read, leases:revoke,
// plus leaseFullRoleID's full-access path policy; leaseOtherUserID and
// leaseAdminID hold nothing at either layer until a test grants it
// directly, the same "deliberately empty by default" convention
// newTestSecretEnv's nobodyID already establishes.
func newTestLeaseEnv(t *testing.T) *testLeaseEnv {
	t.Helper()
	leases := mocks.NewFakeLeaseRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := NewRBACService(rbacRepo)
	users := mocks.NewFakeUserRepository()
	saRepo := mocks.NewFakeServiceAccountRepository()
	policyRepo := mocks.NewFakeSecretPolicyRepository()
	policySvc := NewSecretPolicyService(policyRepo, users, saRepo, rbacSvc, nil)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)
	provider := leasing.NewDevCredentialProvider()

	for _, id := range []string{leaseOwnerUserID, leaseSAOwnerID} {
		rbacRepo.Grant(id, permSecretsRead)
		rbacRepo.Grant(id, permLeasesCreate)
		rbacRepo.Grant(id, permLeasesRead)
		rbacRepo.Grant(id, permLeasesRevoke)
	}

	policyRepo.GrantFullAccessToRole(leaseFullRoleID)
	if err := users.GrantRole(t.Context(), &entity.UserRole{UserID: leaseOwnerUserID, RoleID: leaseFullRoleID}); err != nil {
		t.Fatalf("GrantRole(owner): %v", err)
	}
	if err := saRepo.GrantRole(t.Context(), &entity.ServiceAccountRole{ServiceAccountID: leaseSAOwnerID, RoleID: leaseFullRoleID}); err != nil {
		t.Fatalf("GrantRole(service account): %v", err)
	}

	minTTL, defaultTTL, maxTTL, maxRenewableLifetime := leaseTestConfig()
	svc := NewLeaseService(LeaseServiceDeps{
		Leases:               leases,
		RBAC:                 rbacSvc,
		Policies:             policySvc,
		Providers:            map[string]leasing.DynamicCredentialProvider{provider.Type(): provider},
		MinTTL:               minTTL,
		DefaultTTL:           defaultTTL,
		MaxTTL:               maxTTL,
		MaxRenewableLifetime: maxRenewableLifetime,
		AuditTx:              auditTx,
	})
	return &testLeaseEnv{
		svc: svc, leases: leases, rbac: rbacRepo, users: users, saRepo: saRepo,
		policies: policyRepo, policySvc: policySvc, audit: audit, provider: provider,
	}
}

func leaseOwner() LeaseIdentity {
	return LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseOwnerUserID}
}

func leaseSAOwner() LeaseIdentity {
	return LeaseIdentity{Type: entity.LeaseOwnerServiceAccount, ID: leaseSAOwnerID}
}

func (e *testLeaseEnv) createLease(t *testing.T, actor LeaseIdentity, ttl time.Duration, renewable bool) *CreateLeaseResult {
	t.Helper()
	result, err := e.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		RequestedTTL: ttl, Renewable: renewable, Actor: actor, IPAddress: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return result
}

// --- creation, TTL clamping, and the credential-exposure boundary ---

func TestLeaseService_Create_Succeeds(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, true)

	if result.Lease.ID == "" || result.Lease.Status != entity.LeaseStatusActive {
		t.Fatalf("Create() lease = %+v, want a persisted active lease", result.Lease)
	}
	if result.Lease.OwnerIdentityType != entity.LeaseOwnerUser || result.Lease.OwnerIdentityID != leaseOwnerUserID {
		t.Errorf("Create() lease owner = %s/%s, want %s/%s", result.Lease.OwnerIdentityType, result.Lease.OwnerIdentityID, entity.LeaseOwnerUser, leaseOwnerUserID)
	}
	if result.Credential.Secret["username"] == "" || result.Credential.Secret["password"] == "" {
		t.Errorf("Create() credential = %+v, want a real username/password", result.Credential)
	}

	// result.Lease is exactly what s.deps.Leases.Create persisted — the
	// leases table has no password column at all (see leasing/postgres's
	// own doc comment on Credential.Secret vs .Metadata), and this is the
	// regression test that keeps it that way: Lease.Metadata must never
	// carry the raw credential, only safe provider context (username,
	// database, role_template).
	for k, v := range result.Lease.Metadata {
		if s, ok := v.(string); ok && s == result.Credential.Secret["password"] {
			t.Errorf("persisted lease metadata[%q] = the raw generated password, want it never persisted to the lease database", k)
		}
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "lease.created" {
			found = true
		}
		// The security checklist's own explicit requirement: no audit
		// entry, ever, may carry the raw credential material.
		for _, v := range e.Metadata {
			if s, ok := v.(string); ok && (s == result.Credential.Secret["password"] || s == result.Credential.Secret["username"]) {
				t.Errorf("audit entry %q leaked credential material in metadata: %v", e.Action, e.Metadata)
			}
		}
	}
	if !found {
		t.Error("no lease.created audit entry was recorded")
	}
}

// TestLeaseService_Create_TTLClampedToConfiguredMaximum reproduces the
// objective's own worked example exactly: requested 4h with a 1h maximum
// yields an effective TTL of 1h, never an error, never the raw request.
func TestLeaseService_Create_TTLClampedToConfiguredMaximum(t *testing.T) {
	env := newTestLeaseEnv(t)
	_, _, maxTTL, _ := leaseTestConfig()
	result := env.createLease(t, leaseOwner(), 4*time.Hour, false)

	if result.Lease.TTL != maxTTL {
		t.Errorf("Create() TTL = %s, want clamped to MaxTTL %s", result.Lease.TTL, maxTTL)
	}
}

func TestLeaseService_Create_OmittedTTLUsesDefault(t *testing.T) {
	env := newTestLeaseEnv(t)
	_, defaultTTL, _, _ := leaseTestConfig()
	result := env.createLease(t, leaseOwner(), 0, false)

	if result.Lease.TTL != defaultTTL {
		t.Errorf("Create() TTL = %s, want DefaultTTL %s", result.Lease.TTL, defaultTTL)
	}
}

func TestLeaseService_Create_TTLBelowMinimumClampedUp(t *testing.T) {
	env := newTestLeaseEnv(t)
	minTTL, _, _, _ := leaseTestConfig()
	result := env.createLease(t, leaseOwner(), time.Second, false)

	if result.Lease.TTL != minTTL {
		t.Errorf("Create() TTL = %s, want clamped up to MinTTL %s", result.Lease.TTL, minTTL)
	}
}

// TestLeaseService_Create_UnknownLeaseTypeRejected proves a request naming
// no registered DynamicCredentialProvider fails before any authorization
// or credential-generation work happens.
func TestLeaseService_Create_UnknownLeaseTypeRejected(t *testing.T) {
	env := newTestLeaseEnv(t)
	_, err := env.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: "aws-iam", ResourcePath: "database/prod/readonly",
		Actor: leaseOwner(), IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, ErrUnknownLeaseType) {
		t.Errorf("Create() with an unregistered lease type, error = %v, want ErrUnknownLeaseType", err)
	}
}

// --- authorization chain: the "must not get dynamic credentials merely
// from static secret access" requirement ---

// TestLeaseService_Create_StaticSecretsReadAloneIsNotEnough is the
// objective's own headline case: a caller who can read static secrets
// (secrets:read + full path-policy access) but was never granted
// leases:create must be refused.
func TestLeaseService_Create_StaticSecretsReadAloneIsNotEnough(t *testing.T) {
	env := newTestLeaseEnv(t)
	env.rbac.Grant(leaseOtherUserID, permSecretsRead)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: leaseOtherUserID, RoleID: leaseFullRoleID}); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}

	_, err := env.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		Actor: LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseOtherUserID}, IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("Create() by a caller with secrets:read but no leases:create, error = %v, want ErrForbidden", err)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "lease.create_denied" {
			found = true
		}
	}
	if !found {
		t.Error("no lease.create_denied audit entry was recorded")
	}
}

func TestLeaseService_Create_NoSecretsReadRejected(t *testing.T) {
	env := newTestLeaseEnv(t)
	env.rbac.Grant(leaseOtherUserID, permLeasesCreate) // holds the lease permission but not the base secrets:read gate

	_, err := env.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		Actor: LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseOtherUserID}, IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("Create() without secrets:read, error = %v, want ErrForbidden", err)
	}
}

func TestLeaseService_Create_PathPolicyDeniesRejected(t *testing.T) {
	env := newTestLeaseEnv(t)
	env.rbac.Grant(leaseOtherUserID, permSecretsRead)
	env.rbac.Grant(leaseOtherUserID, permLeasesCreate)
	// No path-policy role granted at all: the global permission checks
	// pass but SecretPolicyService.Authorize has nothing to allow against.

	_, err := env.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		Actor: LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseOtherUserID}, IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("Create() with no path policy granting this path, error = %v, want ErrForbidden", err)
	}
}

// TestLeaseService_Create_ServiceAccountIsolation proves a service
// account's leases:create grant is checked through
// RBACService.HasServiceAccountPermission (the service_account_roles
// table), never conflated with a same-named user's own grants — the
// "payment-service" scenario the objective names directly.
func TestLeaseService_Create_ServiceAccountIsolation(t *testing.T) {
	env := newTestLeaseEnv(t)
	otherSA := "sa-other-service"
	env.rbac.Grant(otherSA, permSecretsRead) // deliberately no leases:create
	if err := env.saRepo.GrantRole(t.Context(), &entity.ServiceAccountRole{ServiceAccountID: otherSA, RoleID: leaseFullRoleID}); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}

	_, err := env.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		Actor: LeaseIdentity{Type: entity.LeaseOwnerServiceAccount, ID: otherSA}, IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("Create() by a service account without leases:create, error = %v, want ErrForbidden", err)
	}

	// leaseSAOwner(), by contrast, does hold every required grant.
	result := env.createLease(t, leaseSAOwner(), 5*time.Minute, false)
	if result.Lease.OwnerIdentityType != entity.LeaseOwnerServiceAccount {
		t.Errorf("Create() lease owner type = %s, want service_account", result.Lease.OwnerIdentityType)
	}
}

// --- lookup: metadata only, anti-enumeration ---

func TestLeaseService_Get_OwnerCanReadOwnLease(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)

	got, err := env.svc.Get(t.Context(), result.Lease.ID, leaseOwner())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != result.Lease.ID {
		t.Errorf("Get() ID = %q, want %q", got.ID, result.Lease.ID)
	}
}

// TestLeaseService_Get_CrossUserAccessDenied is the cross-user lease
// isolation case: another authenticated user who is not the owner and
// holds no leases:read must not be able to look this lease up — reported
// as ErrNotFound, never ErrForbidden, so the lookup itself can't be used
// to confirm the lease ID is valid.
func TestLeaseService_Get_CrossUserAccessDenied(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)

	_, err := env.svc.Get(t.Context(), result.Lease.ID, LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseOtherUserID})
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("Get() by a non-owner without leases:read, error = %v, want ErrNotFound", err)
	}
}

func TestLeaseService_Get_AdministratorWithLeasesReadCanReadAnyLease(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)
	env.rbac.Grant(leaseAdminID, permLeasesRead)

	got, err := env.svc.Get(t.Context(), result.Lease.ID, LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseAdminID})
	if err != nil {
		t.Fatalf("Get() by an administrator holding leases:read, error = %v", err)
	}
	if got.ID != result.Lease.ID {
		t.Errorf("Get() ID = %q, want %q", got.ID, result.Lease.ID)
	}
}

func TestLeaseService_Get_UnknownLeaseIDReportsNotFound(t *testing.T) {
	env := newTestLeaseEnv(t)
	_, err := env.svc.Get(t.Context(), "lease-does-not-exist", leaseOwner())
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("Get() for an unknown lease ID, error = %v, want ErrNotFound", err)
	}
}

// TestLeaseService_Get_ExpiredLeaseReflectsExpiredStatusEvenBeforeCleanupRuns
// proves the "authorization must also check expiration so an expired
// lease cannot remain usable merely because a cleanup worker has not run
// yet" requirement directly: a lease whose persisted Status column is
// still "active" (the cleanup worker hasn't reached it) must be reported
// as expired the instant its ExpiresAt has passed.
func TestLeaseService_Get_ExpiredLeaseReflectsExpiredStatusEvenBeforeCleanupRuns(t *testing.T) {
	env := newTestLeaseEnv(t)
	seeded := env.leases.Seed(&entity.Lease{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		OwnerIdentityType: entity.LeaseOwnerUser, OwnerIdentityID: leaseOwnerUserID,
		Status: entity.LeaseStatusActive, ExpiresAt: time.Now().Add(-time.Minute),
	})

	got, err := env.svc.Get(t.Context(), seeded.ID, leaseOwner())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Status != entity.LeaseStatusExpired {
		t.Errorf("Get() Status = %q, want expired (even though the persisted row still says active)", got.Status)
	}
}

// --- renewal ---

func TestLeaseService_Renew_ExtendsExpiryForRenewableLease(t *testing.T) {
	env := newTestLeaseEnv(t)
	// Renewal requests a longer window than the original TTL — a large
	// enough gap (5m vs. 20m) that the assertion below is robust to
	// coarse clock resolution, never dependent on two time.Now() calls
	// landing in different ticks.
	result := env.createLease(t, leaseOwner(), 5*time.Minute, true)
	oldExpiry := result.Lease.ExpiresAt

	renewed, err := env.svc.Renew(t.Context(), result.Lease.ID, 20*time.Minute, leaseOwner(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if !renewed.ExpiresAt.After(oldExpiry) {
		t.Errorf("Renew() ExpiresAt = %s, want after the original %s", renewed.ExpiresAt, oldExpiry)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "lease.renewed" {
			found = true
		}
	}
	if !found {
		t.Error("no lease.renewed audit entry was recorded")
	}
}

func TestLeaseService_Renew_NonRenewableLeaseRejected(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)

	_, err := env.svc.Renew(t.Context(), result.Lease.ID, 5*time.Minute, leaseOwner(), "203.0.113.10")
	if !errors.Is(err, ErrLeaseNotRenewable) {
		t.Errorf("Renew() on a non-renewable lease, error = %v, want ErrLeaseNotRenewable", err)
	}
}

func TestLeaseService_Renew_RevokedLeaseRejected(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, true)
	if err := env.svc.Revoke(t.Context(), result.Lease.ID, "no longer needed", leaseOwner(), "203.0.113.10"); err != nil {
		t.Fatalf("Revoke(): %v", err)
	}

	_, err := env.svc.Renew(t.Context(), result.Lease.ID, 5*time.Minute, leaseOwner(), "203.0.113.10")
	if !errors.Is(err, ErrLeaseNotActive) {
		t.Errorf("Renew() on a revoked lease, error = %v, want ErrLeaseNotActive", err)
	}
}

func TestLeaseService_Renew_ExpiredLeaseRejected(t *testing.T) {
	env := newTestLeaseEnv(t)
	seeded := env.leases.Seed(&entity.Lease{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		OwnerIdentityType: entity.LeaseOwnerUser, OwnerIdentityID: leaseOwnerUserID,
		Status: entity.LeaseStatusActive, Renewable: true, ExpiresAt: time.Now().Add(-time.Minute),
	})

	_, err := env.svc.Renew(t.Context(), seeded.ID, 5*time.Minute, leaseOwner(), "203.0.113.10")
	if !errors.Is(err, ErrLeaseNotActive) {
		t.Errorf("Renew() on an expired-but-not-yet-swept lease, error = %v, want ErrLeaseNotActive", err)
	}
}

// TestLeaseService_Renew_CrossUserRenewalDenied proves renewal has no
// administrator bypass at all (see migrations/000031's own doc comment on
// why there is deliberately no leases:renew permission): even a caller
// holding leases:revoke/leases:read cannot renew someone else's lease.
func TestLeaseService_Renew_CrossUserRenewalDenied(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, true)
	env.rbac.Grant(leaseAdminID, permLeasesRead)
	env.rbac.Grant(leaseAdminID, permLeasesRevoke)

	_, err := env.svc.Renew(t.Context(), result.Lease.ID, 5*time.Minute, LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseAdminID}, "203.0.113.10")
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("Renew() by a non-owner administrator, error = %v, want ErrNotFound (no admin bypass exists for renewal)", err)
	}
}

func TestLeaseService_Renew_ClampedToMaxTTLPerRenewal(t *testing.T) {
	env := newTestLeaseEnv(t)
	_, _, maxTTL, _ := leaseTestConfig()
	result := env.createLease(t, leaseOwner(), time.Minute, true)

	renewed, err := env.svc.Renew(t.Context(), result.Lease.ID, 4*time.Hour, leaseOwner(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if renewed.TTL != maxTTL {
		t.Errorf("Renew() TTL = %s, want clamped to MaxTTL %s", renewed.TTL, maxTTL)
	}
}

// TestLeaseService_Renew_CannotExceedMaxRenewableLifetime proves the
// second, independent ceiling: total lifetime measured from CreatedAt,
// which a sequence of individually-within-MaxTTL renewals could otherwise
// walk past indefinitely.
func TestLeaseService_Renew_CannotExceedMaxRenewableLifetime(t *testing.T) {
	env := newTestLeaseEnv(t)
	_, _, _, maxRenewableLifetime := leaseTestConfig()
	seeded := env.leases.Seed(&entity.Lease{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		OwnerIdentityType: entity.LeaseOwnerUser, OwnerIdentityID: leaseOwnerUserID,
		Status: entity.LeaseStatusActive, Renewable: true,
		CreatedAt: time.Now().Add(-maxRenewableLifetime).Add(-time.Second), // already past its lifetime ceiling
		ExpiresAt: time.Now().Add(time.Minute),
	})

	_, err := env.svc.Renew(t.Context(), seeded.ID, time.Minute, leaseOwner(), "203.0.113.10")
	if !errors.Is(err, ErrLeaseRenewalExceedsMaxLifetime) {
		t.Errorf("Renew() past MaxRenewableLifetime, error = %v, want ErrLeaseRenewalExceedsMaxLifetime", err)
	}
}

func TestLeaseService_Renew_ClampsDownToRemainingLifetimeRatherThanErroring(t *testing.T) {
	env := newTestLeaseEnv(t)
	seeded := env.leases.Seed(&entity.Lease{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		OwnerIdentityType: entity.LeaseOwnerUser, OwnerIdentityID: leaseOwnerUserID,
		Status: entity.LeaseStatusActive, Renewable: true,
		CreatedAt: time.Now().Add(-110 * time.Minute), // 10 minutes of a 2h lifetime remain
		ExpiresAt: time.Now().Add(time.Minute),
	})

	renewed, err := env.svc.Renew(t.Context(), seeded.ID, time.Hour, leaseOwner(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	remaining := time.Until(renewed.ExpiresAt)
	if remaining > 11*time.Minute {
		t.Errorf("Renew() granted %s beyond the lease's remaining lifetime, want clamped to ~10m", remaining)
	}
}

// --- revocation ---

func TestLeaseService_Revoke_OwnerCanRevokeOwnLease(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)

	if err := env.svc.Revoke(t.Context(), result.Lease.ID, "rotated early", leaseOwner(), "203.0.113.10"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	got, err := env.leases.GetByID(t.Context(), result.Lease.ID)
	if err != nil {
		t.Fatalf("GetByID(): %v", err)
	}
	if got.Status != entity.LeaseStatusRevoked {
		t.Errorf("Status after Revoke() = %q, want revoked", got.Status)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "lease.revoked" {
			found = true
		}
	}
	if !found {
		t.Error("no lease.revoked audit entry was recorded")
	}
}

// TestLeaseService_Revoke_CrossUserRevocationDenied is the cross-user
// isolation case for revocation: a non-owner without leases:revoke must
// not be able to revoke someone else's lease.
func TestLeaseService_Revoke_CrossUserRevocationDenied(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)

	err := env.svc.Revoke(t.Context(), result.Lease.ID, "", LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseOtherUserID}, "203.0.113.10")
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("Revoke() by a non-owner without leases:revoke, error = %v, want ErrNotFound", err)
	}
	got, getErr := env.leases.GetByID(t.Context(), result.Lease.ID)
	if getErr != nil {
		t.Fatalf("GetByID(): %v", getErr)
	}
	if got.Status != entity.LeaseStatusActive {
		t.Errorf("Status after a denied cross-user Revoke() = %q, want still active", got.Status)
	}
}

func TestLeaseService_Revoke_AdministratorWithLeasesRevokeCanRevokeAnyLease(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)
	env.rbac.Grant(leaseAdminID, permLeasesRevoke)

	if err := env.svc.Revoke(t.Context(), result.Lease.ID, "policy violation", LeaseIdentity{Type: entity.LeaseOwnerUser, ID: leaseAdminID}, "203.0.113.10"); err != nil {
		t.Fatalf("Revoke() by an administrator holding leases:revoke, error = %v", err)
	}
}

// TestLeaseService_Revoke_IsIdempotent proves a second revoke on an
// already-revoked lease is a safe no-op — never a second
// lease.revoked/dynamic_credential.revoked audit entry.
func TestLeaseService_Revoke_IsIdempotent(t *testing.T) {
	env := newTestLeaseEnv(t)
	result := env.createLease(t, leaseOwner(), 5*time.Minute, false)

	if err := env.svc.Revoke(t.Context(), result.Lease.ID, "first", leaseOwner(), "203.0.113.10"); err != nil {
		t.Fatalf("first Revoke(): %v", err)
	}
	if err := env.svc.Revoke(t.Context(), result.Lease.ID, "second", leaseOwner(), "203.0.113.10"); err != nil {
		t.Fatalf("second Revoke(): %v", err)
	}

	count := 0
	for _, e := range env.audit.Entries {
		if e.Action == "lease.revoked" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("lease.revoked audit entries = %d, want exactly 1 (revocation must be idempotent)", count)
	}
}

// --- expiration cleanup ---

func TestLeaseService_ExpireOverdue_TransitionsAndAuditsOverdueLeasesOnly(t *testing.T) {
	env := newTestLeaseEnv(t)
	stillGood := env.createLease(t, leaseOwner(), time.Hour, false)
	overdue := env.leases.Seed(&entity.Lease{
		OrganizationID: leaseTestOrgID, LeaseType: leaseTestLeaseTyp, ResourcePath: "database/prod/readonly",
		OwnerIdentityType: entity.LeaseOwnerUser, OwnerIdentityID: leaseOwnerUserID,
		Status: entity.LeaseStatusActive, ExpiresAt: time.Now().Add(-time.Minute),
	})

	n, err := env.svc.ExpireOverdue(t.Context())
	if err != nil {
		t.Fatalf("ExpireOverdue() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("ExpireOverdue() transitioned %d leases, want 1", n)
	}

	got, err := env.leases.GetByID(t.Context(), overdue.ID)
	if err != nil {
		t.Fatalf("GetByID(overdue): %v", err)
	}
	if got.Status != entity.LeaseStatusExpired {
		t.Errorf("overdue lease Status = %q, want expired", got.Status)
	}

	stillGoodRow, err := env.leases.GetByID(t.Context(), stillGood.Lease.ID)
	if err != nil {
		t.Fatalf("GetByID(stillGood): %v", err)
	}
	if stillGoodRow.Status != entity.LeaseStatusActive {
		t.Errorf("not-yet-expired lease Status = %q, want still active", stillGoodRow.Status)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "lease.expired" {
			found = true
			if e.ActorType != entity.AuditActorSystem {
				t.Errorf("lease.expired ActorType = %q, want system — nobody requested this transition", e.ActorType)
			}
		}
	}
	if !found {
		t.Error("no lease.expired audit entry was recorded")
	}
}

// --- failure safety ---

// spyCredentialProvider wraps leasing.DevCredentialProvider, recording
// every RevokeCredential call it receives — the only way to observe,
// from a unit test, that Create's own compensating-revoke path actually
// fired (DevCredentialProvider's real RevokeCredential is an untracked
// no-op; see that type's own doc comment).
type spyCredentialProvider struct {
	*leasing.DevCredentialProvider
	revoked  []string
	lastRole string
}

func newSpyCredentialProvider() *spyCredentialProvider {
	return &spyCredentialProvider{DevCredentialProvider: leasing.NewDevCredentialProvider()}
}

func (p *spyCredentialProvider) RevokeCredential(ctx context.Context, providerRef string) error {
	p.revoked = append(p.revoked, providerRef)
	return p.DevCredentialProvider.RevokeCredential(ctx, providerRef)
}

// CreateCredential records the Role it was called with — the only way a
// unit test can observe that LeaseService.Create forwards
// CreateLeaseInput.Role through to leasing.CreateCredentialInput.Role
// opaquely (Sprint 5 Task 3), without needing a provider that actually
// interprets it the way leasing/postgres.Provider does.
func (p *spyCredentialProvider) CreateCredential(ctx context.Context, in leasing.CreateCredentialInput) (leasing.Credential, error) {
	p.lastRole = in.Role
	return p.DevCredentialProvider.CreateCredential(ctx, in)
}

// TestLeaseService_Create_PersistenceFailureCompensatesByRevokingCredential
// is the objective's own explicit "credential created but lease persist
// failed must not leave an unmanaged credential" requirement: when the
// repository write fails after the provider already minted a credential,
// Create must call the provider's RevokeCredential with that same
// credential's ProviderRef before returning the error.
func TestLeaseService_Create_PersistenceFailureCompensatesByRevokingCredential(t *testing.T) {
	env := newTestLeaseEnv(t)
	spy := newSpyCredentialProvider()
	env.svc = NewLeaseService(LeaseServiceDeps{
		Leases: env.leases, RBAC: NewRBACService(env.rbac), Policies: env.policySvc,
		Providers: map[string]leasing.DynamicCredentialProvider{spy.Type(): spy},
		MinTTL:    time.Minute, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, MaxRenewableLifetime: 2 * time.Hour,
		AuditTx: mocks.FakeAuditTx(env.audit),
	})
	env.leases.FailNextCreate = errors.New("simulated database outage")

	_, err := env.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: spy.Type(), ResourcePath: "database/prod/readonly",
		RequestedTTL: 5 * time.Minute, Actor: leaseOwner(), IPAddress: "203.0.113.10",
	})
	if err == nil {
		t.Fatal("Create() with a failing repository unexpectedly succeeded")
	}
	if len(spy.revoked) != 1 {
		t.Fatalf("provider.RevokeCredential was called %d times, want exactly 1 (the compensating revoke)", len(spy.revoked))
	}
}

// TestLeaseService_Create_ForwardsRoleToProviderOpaquely is Sprint 5
// Task 3's own "no provider-specific logic in the generic service"
// property, verified directly: LeaseService.Create must pass
// CreateLeaseInput.Role through to the provider completely unchanged,
// never inspecting, validating, or defaulting it itself — that is
// leasing/postgres.Provider's own job (ErrUnknownRoleTemplate), proven
// separately by that package's own tests.
func TestLeaseService_Create_ForwardsRoleToProviderOpaquely(t *testing.T) {
	env := newTestLeaseEnv(t)
	spy := newSpyCredentialProvider()
	env.svc = NewLeaseService(LeaseServiceDeps{
		Leases: env.leases, RBAC: NewRBACService(env.rbac), Policies: env.policySvc,
		Providers: map[string]leasing.DynamicCredentialProvider{spy.Type(): spy},
		MinTTL:    time.Minute, DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour, MaxRenewableLifetime: 2 * time.Hour,
		AuditTx: mocks.FakeAuditTx(env.audit),
	})

	_, err := env.svc.Create(t.Context(), CreateLeaseInput{
		OrganizationID: leaseTestOrgID, LeaseType: spy.Type(), ResourcePath: "database/prod/readonly",
		RequestedTTL: 5 * time.Minute, Role: "payment-readonly", Actor: leaseOwner(), IPAddress: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if spy.lastRole != "payment-readonly" {
		t.Errorf("provider received Role = %q, want %q", spy.lastRole, "payment-readonly")
	}
}
