//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/database"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/secrets"
	"github.com/acme/auth-service/internal/service"
)

// platformAdminRoleID is the fixed, well-known role ID
// migrations/000021_seed_platform_admin_role.up.sql seeds — holds every
// secrets:* permission (migrations/000022, 000025) among others.
const platformAdminRoleID = "00000000-0000-4000-9000-000000000001"

// developerRoleID (migrations/000023) holds secrets:read and secrets:list
// only — no create/update/delete — used to prove RBAC actually denies
// against the real database, not just the fakes.
const developerRoleID = "00000000-0000-4000-9000-000000000003"

func newTestSecretServiceEnv(t *testing.T, db *sql.DB) *service.SecretService {
	t.Helper()
	rbacRepo := postgres.NewRBACRepository(db)
	rbacSvc := service.NewRBACService(rbacRepo)
	secretRepo := postgres.NewSecretRepository(db)
	userRepo := postgres.NewUserRepository(db)
	secretPolicyRepo := postgres.NewSecretPolicyRepository(db)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	provider, err := secrets.NewDevKeyProvider("integration-test-key-1", base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewDevKeyProvider: %v", err)
	}
	enc := secrets.NewEncryptionService(provider)

	auditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return database.WithTx(ctx, db, func(tx *sql.Tx) error {
			return fn(postgres.NewAuditLogRepository(tx))
		})
	}
	secretPolicySvc := service.NewSecretPolicyService(secretPolicyRepo, userRepo, rbacSvc, auditTx)

	return service.NewSecretService(secretRepo, enc, rbacSvc, secretPolicySvc, auditTx)
}

// seedActorWithRole creates a real user (via the real UserRepository) and
// grants it roleID (via the real UserRepository.GrantRole, backed by real
// user_roles rows) — "login" for this test's purposes means "this user's
// ID is what a real authentication flow would have resolved and handed to
// SecretService," the same trust boundary every existing service in this
// codebase (UserService, and now SecretService) already operates on; the
// login flow itself is proven separately, end-to-end over real HTTP, by
// test/e2e. label distinguishes multiple actors seeded within the same
// test (t.Name() alone collides — it doesn't change between calls in the
// same test function, only between subtests).
func seedActorWithRole(t *testing.T, db *sql.DB, roleID, label string) *entity.User {
	t.Helper()
	users := postgres.NewUserRepository(db)
	user := &entity.User{OrganizationID: secretTestOrgID, Email: "secret-svc-it-" + label + "-" + t.Name() + "@example.com", Status: entity.UserStatusActive}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create actor user: %v", err)
	}
	if err := users.GrantRole(context.Background(), &entity.UserRole{UserID: user.ID, RoleID: roleID}); err != nil {
		t.Fatalf("grant role: %v", err)
	}
	return user
}

// seedActorWithoutRole creates a real, genuinely-authenticated-shaped
// user with zero role grants — the "authenticated but holds no
// permissions at all" case, distinct from an empty ActorUserID
// (unauthenticated), which internal/service/secret_service_test.go's
// fake-backed tests already cover.
func seedActorWithoutRole(t *testing.T, db *sql.DB) *entity.User {
	t.Helper()
	users := postgres.NewUserRepository(db)
	user := &entity.User{OrganizationID: secretTestOrgID, Email: "secret-svc-it-norole-" + t.Name() + "@example.com", Status: entity.UserStatusActive}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatalf("create actor user: %v", err)
	}
	return user
}

// TestSecretService_FullLifecycle_RealAuthorizationAndEncryption is the
// end-to-end scenario: create a real user, grant it the Platform
// Administrator role (which carries every secrets:* permission), use that
// user's ID as an authenticated actor, create a secret through
// SecretService (real RBAC check against real user_roles/role_permissions,
// real AES-256-GCM encryption, real Postgres persistence), verify the raw
// database row is genuinely encrypted, read it back and verify the exact
// plaintext returns to an authorized caller, update it and verify a new
// version, verify version 1 is untouched, delete it, and verify a normal
// read afterward fails.
func TestSecretService_FullLifecycle_RealAuthorizationAndEncryption(t *testing.T) {
	db := connectForRegisterTest(t)
	svc := newTestSecretServiceEnv(t, db)
	actor := seedActorWithRole(t, db, platformAdminRoleID, "actor")
	ctx := context.Background()
	const path = "app-lifecycle/db/credentials"

	// Create Secret
	original := map[string]string{"username": "app_user", "password": "SuperSecret", "host": "db.internal", "port": "5432"}
	created, err := svc.CreateSecret(ctx, service.CreateSecretInput{
		OrganizationID: secretTestOrgID, Path: path, Payload: original, ActorUserID: actor.ID, IPAddress: "203.0.113.55",
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	if created.CurrentVersion != 1 {
		t.Fatalf("CreateSecret() CurrentVersion = %d, want 1", created.CurrentVersion)
	}

	// Verify encrypted database record: raw SQL, bypassing the service
	// entirely, the same way a reviewer would check by hand with psql.
	var ciphertext []byte
	var algorithm string
	err = db.QueryRowContext(ctx, `SELECT ciphertext, algorithm FROM secret_versions WHERE secret_id = $1 AND version = 1`, created.ID).
		Scan(&ciphertext, &algorithm)
	if err != nil {
		t.Fatalf("reading raw secret_versions row: %v", err)
	}
	if algorithm != secrets.AlgorithmAES256GCM {
		t.Errorf("stored algorithm = %q, want %q", algorithm, secrets.AlgorithmAES256GCM)
	}
	for _, v := range original {
		if strings.Contains(string(ciphertext), v) {
			t.Errorf("raw ciphertext contains plaintext value %q — payload was not encrypted", v)
		}
	}

	// Read Secret -> correct plaintext to an authorized caller
	val, err := svc.GetSecret(ctx, service.GetSecretInput{OrganizationID: secretTestOrgID, Path: path, ActorUserID: actor.ID, IPAddress: "203.0.113.55"})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	for k, want := range original {
		if val.Payload[k] != want {
			t.Errorf("GetSecret() Payload[%q] = %q, want %q", k, val.Payload[k], want)
		}
	}

	// Update Secret -> Version 2
	rotated := map[string]string{"username": "app_user", "password": "RotatedSecret", "host": "db.internal", "port": "5432"}
	updated, err := svc.UpdateSecret(ctx, service.UpdateSecretInput{
		OrganizationID: secretTestOrgID, Path: path, ExpectedVersion: created.CurrentVersion, Payload: rotated, ActorUserID: actor.ID, IPAddress: "203.0.113.55",
	})
	if err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
	if updated.CurrentVersion != 2 {
		t.Fatalf("UpdateSecret() CurrentVersion = %d, want 2", updated.CurrentVersion)
	}

	// Read Version 1 -> unchanged
	v1 := 1
	valV1, err := svc.GetSecret(ctx, service.GetSecretInput{OrganizationID: secretTestOrgID, Path: path, Version: &v1, ActorUserID: actor.ID})
	if err != nil {
		t.Fatalf("GetSecret(version 1) error = %v", err)
	}
	if valV1.Payload["password"] != "SuperSecret" {
		t.Errorf("GetSecret(version 1) after update, password = %q, want the original %q — version 1 must be immutable", valV1.Payload["password"], "SuperSecret")
	}

	// Current read reflects version 2
	valCurrent, err := svc.GetSecret(ctx, service.GetSecretInput{OrganizationID: secretTestOrgID, Path: path, ActorUserID: actor.ID})
	if err != nil {
		t.Fatalf("GetSecret(current) error = %v", err)
	}
	if valCurrent.Version != 2 || valCurrent.Payload["password"] != "RotatedSecret" {
		t.Errorf("GetSecret(current) = version %d, password %q, want version 2 with the rotated password", valCurrent.Version, valCurrent.Payload["password"])
	}

	// Delete Secret
	if err := svc.DeleteSecret(ctx, service.DeleteSecretInput{OrganizationID: secretTestOrgID, Path: path, ActorUserID: actor.ID, IPAddress: "203.0.113.55"}); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}

	// Normal read fails
	if _, err := svc.GetSecret(ctx, service.GetSecretInput{OrganizationID: secretTestOrgID, Path: path, ActorUserID: actor.ID}); !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetSecret() after delete, error = %v, want entity.ErrNotFound", err)
	}

	// Real audit trail exists for every step, generated against the real,
	// hash-chained audit_logs table (Sprint 2's own AuditLogRepository —
	// unmodified, reused as-is).
	rows, err := db.QueryContext(ctx, `SELECT action FROM audit_logs WHERE resource_id = $1 ORDER BY occurred_at`, created.ID)
	if err != nil {
		t.Fatalf("querying audit_logs: %v", err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scanning audit action: %v", err)
		}
		actions = append(actions, a)
	}
	wantActions := map[string]bool{"secret.created": false, "secret.read": false, "secret.updated": false, "secret.deleted": false}
	for _, a := range actions {
		if _, ok := wantActions[a]; ok {
			wantActions[a] = true
		}
	}
	for action, found := range wantActions {
		if !found {
			t.Errorf("no real audit_logs row found for action %q (recorded actions: %v)", action, actions)
		}
	}
}

// TestSecretService_RealRBAC_DeniesInsufficientRole proves authorization
// against the real database: a user holding only the Developer role
// (secrets:read/secrets:list, no create/update/delete — migrations/000023)
// can read but cannot create, update, or delete, and an authenticated
// caller with no role at all is denied outright — exercising
// service.RBACService.HasPermission -> repository.RBACRepository.UserHasPermission
// against real user_roles/role_permissions/permissions rows, not the fake
// used by internal/service's own unit tests.
func TestSecretService_RealRBAC_DeniesInsufficientRole(t *testing.T) {
	db := connectForRegisterTest(t)
	svc := newTestSecretServiceEnv(t, db)
	ctx := context.Background()

	admin := seedActorWithRole(t, db, platformAdminRoleID, "admin")
	_, err := svc.CreateSecret(ctx, service.CreateSecretInput{
		OrganizationID: secretTestOrgID, Path: "app-rbac/seed-secret", Payload: map[string]string{"k": "v"}, ActorUserID: admin.ID,
	})
	if err != nil {
		t.Fatalf("CreateSecret() by admin, error = %v", err)
	}

	developer := seedActorWithRole(t, db, developerRoleID, "developer")

	if _, err := svc.GetSecret(ctx, service.GetSecretInput{OrganizationID: secretTestOrgID, Path: "app-rbac/seed-secret", ActorUserID: developer.ID}); err != nil {
		t.Errorf("GetSecret() by a Developer (holds secrets:read), error = %v, want nil", err)
	}

	if _, err := svc.CreateSecret(ctx, service.CreateSecretInput{
		OrganizationID: secretTestOrgID, Path: "app-rbac/developer-attempt", Payload: map[string]string{"k": "v"}, ActorUserID: developer.ID,
	}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("CreateSecret() by a Developer (no secrets:create), error = %v, want entity.ErrForbidden", err)
	}

	if _, err := svc.UpdateSecret(ctx, service.UpdateSecretInput{
		OrganizationID: secretTestOrgID, Path: "app-rbac/seed-secret", ExpectedVersion: 1, Payload: map[string]string{"k": "v2"}, ActorUserID: developer.ID,
	}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("UpdateSecret() by a Developer (no secrets:update), error = %v, want entity.ErrForbidden", err)
	}

	if err := svc.DeleteSecret(ctx, service.DeleteSecretInput{OrganizationID: secretTestOrgID, Path: "app-rbac/seed-secret", ActorUserID: developer.ID}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("DeleteSecret() by a Developer (no secrets:delete), error = %v, want entity.ErrForbidden", err)
	}

	// A real, authenticated user with no role grants at all is denied too.
	noRoleUser := seedActorWithoutRole(t, db)
	if _, err := svc.GetSecret(ctx, service.GetSecretInput{OrganizationID: secretTestOrgID, Path: "app-rbac/seed-secret", ActorUserID: noRoleUser.ID}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret() by a user with no role grants, error = %v, want entity.ErrForbidden", err)
	}
}
