package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/secrets"
)

const (
	testOrgID = "org-1"
	ownerID   = "user-owner-1"
	readerID  = "user-reader-1"
	nobodyID  = "user-nobody-1" // authenticated, but holds no secrets:* grants
	// updaterID holds secrets:read + secrets:update but deliberately not
	// secrets:rollback — the one identity in this fixture that exists
	// specifically to prove "read != rollback" and "update != rollback"
	// (permSecretsRollback's own doc comment) against a caller who is
	// otherwise a fully legitimate secret writer, not merely an
	// unauthenticated or no-permissions-at-all caller the way nobodyID is.
	updaterID = "user-updater-1"
)

// testSecretEnv is everything one test needs: a SecretService plus direct
// access to the fakes underneath it, so a test can inspect what was
// actually persisted/audited without going through the service's own
// (deliberately narrow) return types.
type testSecretEnv struct {
	svc             *SecretService
	repo            *mocks.FakeSecretRepository
	rbac            *mocks.FakeRBACRepository
	users           *mocks.FakeUserRepository
	serviceAccounts *mocks.FakeServiceAccountRepository
	policies        *mocks.FakeSecretPolicyRepository
	policySvc       *SecretPolicyService
	audit           *mocks.FakeAuditLogRepository
	enc             *secrets.EncryptionService
	// rawKey is the decoded 32-byte AES key backing enc's DevKeyProvider —
	// captured here (never exposed by secrets.KeyProvider itself, by
	// design) purely so TestSecretService_AuditNeverContainsPlaintextOrKeys
	// can assert this exact byte sequence never appears in anything this
	// service persists.
	rawKey []byte
}

func newTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}

// testFullAccessRoleID is the fake role newTestSecretEnv grants ownerID
// and readerID — carrying a policy equivalent to migrations/000027's own
// backward-compatibility default (path "*", every action, allow). This is
// what keeps every test written before Sprint 4 Task 2 existed passing
// unchanged: the global secrets:* permission grants below still gate
// which actions each user may attempt, exactly as before, and this role's
// full-access policy means the new path-policy layer never itself
// becomes the reason an existing test's expectation changes. Tests that
// exist specifically to exercise path-restricted policies construct their
// own narrower policy instead of using this role — see
// TestSecretService_PathPolicy* below.
const testFullAccessRoleID = "role-full-access"

// newTestSecretEnv wires a SecretService against in-memory fakes and a
// real secrets.EncryptionService (real AES-256-GCM, a freshly generated
// test-only key) — no database, real business logic, real cryptography.
// ownerID and readerID are pre-granted every secrets:* permission and
// secrets:read respectively (unchanged from before Task 2), plus
// testFullAccessRoleID's full-access path policy (new — see that
// constant's own doc comment); nobodyID is deliberately granted nothing
// at either layer.
func newTestSecretEnv(t *testing.T) *testSecretEnv {
	t.Helper()
	repo := mocks.NewFakeSecretRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := NewRBACService(rbacRepo)
	users := mocks.NewFakeUserRepository()
	policyRepo := mocks.NewFakeSecretPolicyRepository()
	serviceAccounts := mocks.NewFakeServiceAccountRepository()
	policySvc := NewSecretPolicyService(policyRepo, users, serviceAccounts, rbacSvc, nil)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	rawKey := newTestKey(t)
	provider, err := secrets.NewDevKeyProvider("test-key-1", base64.StdEncoding.EncodeToString(rawKey))
	if err != nil {
		t.Fatalf("NewDevKeyProvider: %v", err)
	}
	enc := secrets.NewEncryptionService(provider)

	rbacRepo.Grant(ownerID, permSecretsCreate)
	rbacRepo.Grant(ownerID, permSecretsRead)
	rbacRepo.Grant(ownerID, permSecretsUpdate)
	rbacRepo.Grant(ownerID, permSecretsDelete)
	rbacRepo.Grant(ownerID, permSecretsList)
	rbacRepo.Grant(ownerID, permSecretsRollback)
	rbacRepo.Grant(readerID, permSecretsRead)
	rbacRepo.Grant(updaterID, permSecretsRead)
	rbacRepo.Grant(updaterID, permSecretsUpdate)

	policyRepo.GrantFullAccessToRole(testFullAccessRoleID)
	if err := users.GrantRole(t.Context(), &entity.UserRole{UserID: ownerID, RoleID: testFullAccessRoleID}); err != nil {
		t.Fatalf("GrantRole(owner): %v", err)
	}
	if err := users.GrantRole(t.Context(), &entity.UserRole{UserID: readerID, RoleID: testFullAccessRoleID}); err != nil {
		t.Fatalf("GrantRole(reader): %v", err)
	}
	if err := users.GrantRole(t.Context(), &entity.UserRole{UserID: updaterID, RoleID: testFullAccessRoleID}); err != nil {
		t.Fatalf("GrantRole(updater): %v", err)
	}

	svc := NewSecretService(repo, enc, rbacSvc, policySvc, auditTx)
	return &testSecretEnv{
		svc: svc, repo: repo, rbac: rbacRepo, users: users, serviceAccounts: serviceAccounts,
		policies: policyRepo, policySvc: policySvc, audit: audit, enc: enc, rawKey: rawKey,
	}
}

// newTestKeyBase64 is the standalone form TestSecretService_WrongKey_FailsSafely
// needs for its second, independently-keyed EncryptionService.
func newTestKeyBase64(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(newTestKey(t))
}

func validPayload() map[string]string {
	return map[string]string{"username": "app_user", "password": "SuperSecret", "host": "db.internal", "port": "5432"}
}

func createValidSecret(t *testing.T, env *testSecretEnv, path string) SecretMetadata {
	t.Helper()
	meta, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: path, Payload: validPayload(), ActorUserID: ownerID, IPAddress: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	return meta
}

// --- 1 & 2. Unauthenticated user cannot create/read ---

func TestSecretService_Unauthenticated_CannotCreate(t *testing.T) {
	env := newTestSecretEnv(t)
	_, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "app/db", Payload: validPayload(), ActorUserID: "",
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("CreateSecret() with no ActorUserID, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_Unauthenticated_CannotRead(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")
	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: ""})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret() with no ActorUserID, error = %v, want entity.ErrForbidden", err)
	}
}

// --- 3-6. Authenticated but unauthorized (missing the specific permission) ---

func TestSecretService_WithoutSecretsRead_CannotRead(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")
	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: nobodyID})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret() without secrets:read, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_WithoutSecretsCreate_CannotCreate(t *testing.T) {
	env := newTestSecretEnv(t)
	_, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "app/db", Payload: validPayload(), ActorUserID: nobodyID,
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("CreateSecret() without secrets:create, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_WithoutSecretsUpdate_CannotUpdate(t *testing.T) {
	env := newTestSecretEnv(t)
	meta := createValidSecret(t, env, "app/db")
	_, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/db", ExpectedVersion: meta.CurrentVersion, Payload: validPayload(), ActorUserID: nobodyID,
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("UpdateSecret() without secrets:update, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_WithoutSecretsDelete_CannotDelete(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")
	err := env.svc.DeleteSecret(t.Context(), DeleteSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: nobodyID})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("DeleteSecret() without secrets:delete, error = %v, want entity.ErrForbidden", err)
	}
}

// --- 7. Authorized user can create secret ---

func TestSecretService_AuthorizedUser_CanCreate(t *testing.T) {
	env := newTestSecretEnv(t)
	meta := createValidSecret(t, env, "app/db")
	if meta.ID == "" {
		t.Fatal("CreateSecret() returned no ID")
	}
	if meta.CurrentVersion != 1 {
		t.Errorf("CreateSecret() CurrentVersion = %d, want 1", meta.CurrentVersion)
	}
	if meta.Path != "app/db" {
		t.Errorf("CreateSecret() Path = %q, want %q", meta.Path, "app/db")
	}
}

// --- 8 & 9. Encrypted before persistence; plaintext not stored ---
//
// This is the service-level half of the proof: the fake repository
// receives only what SecretService.CreateSecret hands it, and this test
// shows that's never the plaintext, regardless of which
// repository.SecretRepository implementation is behind it. The
// authoritative, real-database half is
// test/integration/secret_service_test.go, which performs the identical
// check against real PostgreSQL.
func TestSecretService_PayloadEncryptedBeforePersistence(t *testing.T) {
	env := newTestSecretEnv(t)
	const marker = "THIS_IS_TEST_SECRET_VALUE"
	_, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "app/marker", Payload: map[string]string{"value": marker}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	secret, err := env.repo.GetByPath(t.Context(), testOrgID, "app/marker")
	if err != nil {
		t.Fatalf("GetByPath() error = %v", err)
	}
	version, err := env.repo.GetVersion(t.Context(), secret.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if strings.Contains(string(version.Ciphertext), marker) {
		t.Error("stored Ciphertext contains the plaintext marker — payload was not encrypted before persistence")
	}
	if len(version.Nonce) == 0 || len(version.AuthTag) == 0 || len(version.WrappedDEK) == 0 || version.KeyID == "" {
		t.Error("stored version is missing encryption metadata — CreateSecret did not go through EncryptionService")
	}
}

// --- 10. Authorized user can retrieve secret ---

func TestSecretService_AuthorizedUser_CanRetrieve(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")

	val, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: readerID})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if val.Version != 1 {
		t.Errorf("GetSecret() Version = %d, want 1", val.Version)
	}
	want := validPayload()
	if len(val.Payload) != len(want) {
		t.Fatalf("GetSecret() Payload = %v, want %v", val.Payload, want)
	}
	for k, v := range want {
		if val.Payload[k] != v {
			t.Errorf("GetSecret() Payload[%q] = %q, want %q", k, val.Payload[k], v)
		}
	}
}

// --- 11. Wrong key fails safely ---

func TestSecretService_WrongKey_FailsSafely(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")

	t.Run("same key ID, different key material", func(t *testing.T) {
		// Simulates an operator misconfiguration — the right key ID, wrong
		// bytes loaded under it — not a missing key. Fails at the DEK-unwrap
		// authentication step, the same way secrets.TestDecrypt_WrongKey_Fails
		// proves at the crypto-package level.
		otherProvider, err := secrets.NewDevKeyProvider("test-key-1", newTestKeyBase64(t))
		if err != nil {
			t.Fatalf("NewDevKeyProvider: %v", err)
		}
		otherSvc := NewSecretService(env.repo, secrets.NewEncryptionService(otherProvider), NewRBACService(env.rbac), env.policySvc, nil)

		_, err = otherSvc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: readerID})
		if !errors.Is(err, secrets.ErrCiphertextInvalid) {
			t.Errorf("GetSecret() with the wrong key material under the same key ID, error = %v, want secrets.ErrCiphertextInvalid", err)
		}
	})

	t.Run("unknown key ID", func(t *testing.T) {
		// A provider that has never heard of the key ID the stored version
		// was encrypted under at all — e.g. a differently-configured
		// environment, or a deleted key.
		otherProvider, err := secrets.NewDevKeyProvider("some-other-key-id", newTestKeyBase64(t))
		if err != nil {
			t.Fatalf("NewDevKeyProvider: %v", err)
		}
		otherSvc := NewSecretService(env.repo, secrets.NewEncryptionService(otherProvider), NewRBACService(env.rbac), env.policySvc, nil)

		_, err = otherSvc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: readerID})
		if !errors.Is(err, secrets.ErrKeyUnavailable) {
			t.Errorf("GetSecret() with an unknown key ID, error = %v, want secrets.ErrKeyUnavailable", err)
		}
	})
}

// --- 12. Tampered ciphertext fails ---

func TestSecretService_TamperedCiphertext_Fails(t *testing.T) {
	env := newTestSecretEnv(t)
	meta := createValidSecret(t, env, "app/db")

	version, err := env.repo.GetVersion(t.Context(), meta.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	version.Ciphertext[0] ^= 0xFF // mutate the fake's own stored bytes directly

	_, err = env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: readerID})
	if !errors.Is(err, secrets.ErrCiphertextInvalid) {
		t.Errorf("GetSecret() of a tampered record, error = %v, want secrets.ErrCiphertextInvalid", err)
	}
}

// --- 13. Updating creates a new version ---

func TestSecretService_Update_CreatesNewVersion(t *testing.T) {
	env := newTestSecretEnv(t)
	meta := createValidSecret(t, env, "app/db")

	updated, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/db", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"password": "RotatedSecret"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
	if updated.CurrentVersion != 2 {
		t.Errorf("UpdateSecret() CurrentVersion = %d, want 2", updated.CurrentVersion)
	}

	val, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: readerID})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if val.Version != 2 || val.Payload["password"] != "RotatedSecret" {
		t.Errorf("GetSecret() after update = version %d, payload %v, want version 2 with the rotated password", val.Version, val.Payload)
	}
}

// --- 14. Historical versions remain unchanged ---

func TestSecretService_HistoricalVersion_RemainsUnchanged(t *testing.T) {
	env := newTestSecretEnv(t)
	meta := createValidSecret(t, env, "app/db") // version 1: validPayload()

	_, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/db", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"password": "RotatedSecret"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}

	v1 := 1
	val, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", Version: &v1, ActorUserID: readerID})
	if err != nil {
		t.Fatalf("GetSecret(version 1) error = %v", err)
	}
	if val.Payload["password"] != "SuperSecret" {
		t.Errorf("GetSecret(version 1) after an update, Payload[password] = %q, want the original %q — version 1 must never change", val.Payload["password"], "SuperSecret")
	}
}

// --- 15. Concurrent updates are handled safely ---

func TestSecretService_ConcurrentUpdates_HandledSafely(t *testing.T) {
	env := newTestSecretEnv(t)
	meta := createValidSecret(t, env, "app/db")

	const concurrency = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, conflicts := 0, 0

	for i := range concurrency {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
				OrganizationID: testOrgID, Path: "app/db", ExpectedVersion: meta.CurrentVersion, // every goroutine expects version 1
				Payload: map[string]string{"password": fmt.Sprintf("value-%d", n)}, ActorUserID: ownerID,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, entity.ErrVersionConflict):
				conflicts++
			default:
				t.Errorf("UpdateSecret() unexpected error = %v", err)
			}
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("successes = %d, want exactly 1 — concurrent updates against the same expected version must not both succeed", successes)
	}
	if successes+conflicts != concurrency {
		t.Errorf("successes(%d) + conflicts(%d) = %d, want %d", successes, conflicts, successes+conflicts, concurrency)
	}

	final, err := env.repo.GetByID(t.Context(), meta.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if final.CurrentVersion != 2 {
		t.Errorf("final CurrentVersion = %d, want 2 (exactly one update must have landed)", final.CurrentVersion)
	}
}

// --- 16. Deleted secrets cannot be normally read ---

func TestSecretService_DeletedSecret_CannotBeNormallyRead(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")

	if err := env.svc.DeleteSecret(t.Context(), DeleteSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: ownerID}); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}

	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: readerID})
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetSecret() of a deleted secret, error = %v, want entity.ErrNotFound", err)
	}
}

// --- 17. Listing never returns secret values ---

func TestSecretService_List_NeverReturnsValues(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db1")
	createValidSecret(t, env, "app/db2")

	// SecretMetadata (ListSecrets' element type) has no field a payload,
	// ciphertext, nonce, or key could occupy — this is a compile-time
	// guarantee, not just a runtime one. The runtime check below confirms
	// the values that *do* come back are exactly what's expected.
	list, err := env.svc.ListSecrets(t.Context(), ListSecretsInput{OrganizationID: testOrgID, ActorUserID: ownerID})
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListSecrets() returned %d secrets, want 2", len(list))
	}
	for _, m := range list {
		if m.Path == "" || m.CurrentVersion != 1 {
			t.Errorf("ListSecrets() entry = %+v, want a populated path and CurrentVersion 1", m)
		}
	}
}

// --- 18. Audit events are generated ---

func TestSecretService_AuditEventsGenerated(t *testing.T) {
	env := newTestSecretEnv(t)
	meta := createValidSecret(t, env, "app/db")
	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: readerID}); err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if _, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/db", ExpectedVersion: meta.CurrentVersion, Payload: validPayload(), ActorUserID: ownerID,
	}); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
	if err := env.svc.DeleteSecret(t.Context(), DeleteSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: ownerID}); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}

	wantActions := []string{"secret.created", "secret.read", "secret.updated", "secret.deleted"}
	for _, action := range wantActions {
		found := false
		for _, e := range env.audit.Entries {
			if e.Action == action {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no audit entry recorded for action %q", action)
		}
	}
}

// --- 19 & 20. Audit logs never contain plaintext or key material ---
//
// See internal/secrets/encryption_test.go's TestErrors_NeverContainSensitiveMaterial
// for the same guarantee proven at the crypto-package boundary (no error
// or Stringer output ever leaks). This test proves it at the audit-trail
// boundary — the one place SecretService itself writes anything durable
// that isn't already covered by test #8/#9's ciphertext check.
func TestSecretService_AuditNeverContainsPlaintextOrKeys(t *testing.T) {
	env := newTestSecretEnv(t)
	const marker = "THIS_IS_TEST_SECRET_VALUE"

	meta, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "app/marker", Payload: map[string]string{"value": marker}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/marker", ActorUserID: readerID}); err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if _, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/marker", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"value": marker + "-v2"}, ActorUserID: ownerID,
	}); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}

	for _, e := range env.audit.Entries {
		encoded, err := json.Marshal(e.Metadata)
		if err != nil {
			t.Fatalf("marshaling audit metadata: %v", err)
		}
		if strings.Contains(string(encoded), marker) {
			t.Errorf("audit entry %q metadata contains the plaintext marker: %s", e.Action, encoded)
		}
		if strings.Contains(string(encoded), string(env.rawKey)) {
			t.Errorf("audit entry %q metadata contains raw key material", e.Action)
		}
	}
}

// --- Sprint 4 Task 2: path-scoped policy authorization, layered on top
// of (never replacing) the secrets:* RBAC checks exercised above.
// testFullAccessRoleID's wildcard policy is what keeps every test above
// this section passing unchanged (see that constant's own doc comment);
// the tests below construct their own narrower policies to exercise the
// new layer directly. ---

func TestSecretService_PathPolicy_DeniesWithoutMatchingPolicy(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")

	const actor = "user-path-no-policy"
	env.rbac.Grant(actor, permSecretsRead)
	// actor holds the global secrets:read permission but is not a member
	// of any role a secret policy is assigned to — deny by default per the
	// objective, even though the RBAC check alone would have allowed this.

	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: actor})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret() with secrets:read but no matching path policy, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_PathPolicy_GlobalPermissionRequiredEvenWithMatchingPolicy(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "app/db")

	const actor = "user-policy-no-permission"
	const role = "role-wildcard-no-rbac"
	env.policies.GrantFullAccessToRole(role)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: actor, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}
	// actor's role carries a "*" allow-everything path policy, but actor
	// was never granted secrets:read itself — "If user lacks secrets:read,
	// Result: DENY even if a path policy exists," per the objective.

	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: actor})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret() with a full-access path policy but no secrets:read permission, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_PathPolicy_AllowsAndDeniesByPath(t *testing.T) {
	env := newTestSecretEnv(t)
	const actor = "user-dev-only"
	const role = "role-dev-only"
	env.rbac.Grant(actor, permSecretsRead)
	env.policies.SeedPolicy(&entity.SecretPolicy{ID: "policy-dev-only", Name: "dev-only"})
	env.policies.SeedRule("policy-dev-only", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow, Actions: []entity.PolicyAction{entity.PolicyActionRead},
	})
	env.policies.AssignRole("policy-dev-only", role)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: actor, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	createValidSecret(t, env, "dev/db")
	createValidSecret(t, env, "prod/db")

	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "dev/db", ActorUserID: actor}); err != nil {
		t.Errorf("GetSecret(dev/db) = %v, want nil (matching dev/* policy)", err)
	}
	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "prod/db", ActorUserID: actor}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret(prod/db) = %v, want entity.ErrForbidden (no matching policy)", err)
	}
}

func TestSecretService_PathPolicy_CreateRespectsPath(t *testing.T) {
	env := newTestSecretEnv(t)
	const actor = "user-dev-creator"
	const role = "role-dev-creator"
	env.rbac.Grant(actor, permSecretsCreate)
	env.policies.SeedPolicy(&entity.SecretPolicy{ID: "policy-dev-create", Name: "dev-create"})
	env.policies.SeedRule("policy-dev-create", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow, Actions: []entity.PolicyAction{entity.PolicyActionCreate},
	})
	env.policies.AssignRole("policy-dev-create", role)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: actor, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	if _, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{OrganizationID: testOrgID, Path: "dev/test", Payload: validPayload(), ActorUserID: actor}); err != nil {
		t.Errorf("CreateSecret(dev/test) = %v, want nil", err)
	}
	if _, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{OrganizationID: testOrgID, Path: "prod/test", Payload: validPayload(), ActorUserID: actor}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("CreateSecret(prod/test) = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_PathPolicy_UpdateAndDeleteRespectPath(t *testing.T) {
	env := newTestSecretEnv(t)
	const actor = "user-dev-writer"
	const role = "role-dev-writer"
	env.rbac.Grant(actor, permSecretsUpdate)
	env.rbac.Grant(actor, permSecretsDelete)
	env.policies.SeedPolicy(&entity.SecretPolicy{ID: "policy-dev-write", Name: "dev-write"})
	env.policies.SeedRule("policy-dev-write", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{entity.PolicyActionUpdate, entity.PolicyActionDelete},
	})
	env.policies.AssignRole("policy-dev-write", role)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: actor, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	devMeta := createValidSecret(t, env, "dev/rotate")
	prodMeta := createValidSecret(t, env, "prod/rotate")

	if _, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "dev/rotate", ExpectedVersion: devMeta.CurrentVersion, Payload: validPayload(), ActorUserID: actor,
	}); err != nil {
		t.Errorf("UpdateSecret(dev/rotate) = %v, want nil", err)
	}
	if _, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "prod/rotate", ExpectedVersion: prodMeta.CurrentVersion, Payload: validPayload(), ActorUserID: actor,
	}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("UpdateSecret(prod/rotate) = %v, want entity.ErrForbidden", err)
	}

	if err := env.svc.DeleteSecret(t.Context(), DeleteSecretInput{OrganizationID: testOrgID, Path: "prod/rotate", ActorUserID: actor}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("DeleteSecret(prod/rotate) = %v, want entity.ErrForbidden", err)
	}
	if err := env.svc.DeleteSecret(t.Context(), DeleteSecretInput{OrganizationID: testOrgID, Path: "dev/rotate", ActorUserID: actor}); err != nil {
		t.Errorf("DeleteSecret(dev/rotate) = %v, want nil", err)
	}
}

// --- AUDIT: denied secret access must leave a trail (identity, action,
// canonical path, result), at both the global-permission layer and the
// path-policy layer — before this, a rejected caller left no audit
// record at all. ---

func TestSecretService_DeniedAccess_AuditedAtPermissionLayer(t *testing.T) {
	env := newTestSecretEnv(t)
	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/db", ActorUserID: nobodyID, IPAddress: "203.0.113.99"})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Fatalf("GetSecret() error = %v, want entity.ErrForbidden", err)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action != "secret.access_denied" {
			continue
		}
		found = true
		if e.Result != entity.AuditResultDenied {
			t.Errorf("audit entry Result = %q, want %q", e.Result, entity.AuditResultDenied)
		}
		if e.ActorID == nil || *e.ActorID != nobodyID {
			t.Errorf("audit entry ActorID = %v, want %q", e.ActorID, nobodyID)
		}
		if e.ResourceID == nil || *e.ResourceID != "app/db" {
			t.Errorf("audit entry ResourceID = %v, want the canonical path %q", e.ResourceID, "app/db")
		}
	}
	if !found {
		t.Error("no secret.access_denied audit entry was recorded for a permission-layer denial")
	}
}

func TestSecretService_DeniedAccess_AuditedAtPathPolicyLayer(t *testing.T) {
	env := newTestSecretEnv(t)
	createValidSecret(t, env, "prod/db")

	const actor = "user-audit-path-denied"
	env.rbac.Grant(actor, permSecretsRead)

	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "prod/db", ActorUserID: actor, IPAddress: "203.0.113.98"})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Fatalf("GetSecret() error = %v, want entity.ErrForbidden", err)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "secret.access_denied" && e.ActorID != nil && *e.ActorID == actor {
			found = true
			if e.Result != entity.AuditResultDenied {
				t.Errorf("audit entry Result = %q, want %q", e.Result, entity.AuditResultDenied)
			}
		}
	}
	if !found {
		t.Error("no secret.access_denied audit entry was recorded for a path-policy-layer denial (global permission held, no matching policy)")
	}
}

// --- LIST AUTHORIZATION: the objective's own dev/database + dev/api +
// prod/database + prod/payment example, reproduced exactly. ---

func TestSecretService_PathPolicy_ListFiltersUnauthorizedPaths(t *testing.T) {
	env := newTestSecretEnv(t)
	const actor = "user-dev-lister"
	const role = "role-dev-lister"
	env.rbac.Grant(actor, permSecretsList)
	env.policies.SeedPolicy(&entity.SecretPolicy{ID: "policy-dev-list", Name: "dev-list"})
	env.policies.SeedRule("policy-dev-list", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow, Actions: []entity.PolicyAction{entity.PolicyActionList},
	})
	env.policies.AssignRole("policy-dev-list", role)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: actor, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	createValidSecret(t, env, "dev/database")
	createValidSecret(t, env, "dev/api")
	createValidSecret(t, env, "prod/database")
	createValidSecret(t, env, "prod/payment")

	out, err := env.svc.ListSecrets(t.Context(), ListSecretsInput{OrganizationID: testOrgID, ActorUserID: actor})
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	got := map[string]bool{}
	for _, m := range out {
		got[m.Path] = true
	}
	want := map[string]bool{"dev/database": true, "dev/api": true}
	if len(got) != len(want) {
		t.Fatalf("ListSecrets() paths = %v, want exactly %v", got, want)
	}
	for p := range got {
		if !want[p] {
			t.Errorf("ListSecrets() unexpectedly included unauthorized path %q — must never reveal metadata for a path the caller has no policy for", p)
		}
	}
}

// --- Sprint 5 Task 1: the objective's own worked example, exercised
// directly — payment-service (a service account) -> payment-reader (a
// role) -> a policy granting prod/payment/* read -> ALLOW, and DENY
// outside that path. These are the service-account-actor mirror of
// TestSecretService_PathPolicy_AllowsAndDeniesByPath above, proving the
// same authorization chain works when the actor row lives in
// service_account_roles instead of user_roles. ---

func TestSecretService_ServiceAccountActor_AllowedWithinGrantedPolicyPath(t *testing.T) {
	env := newTestSecretEnv(t)
	const serviceAccountID = "sa-payment-service"
	const role = "role-payment-reader"
	env.rbac.Grant(serviceAccountID, permSecretsRead)
	env.policies.SeedPolicy(&entity.SecretPolicy{ID: "policy-payment-read", Name: "payment-read"})
	env.policies.SeedRule("policy-payment-read", &entity.SecretPolicyRule{
		PathPattern: "prod/payment/*", Effect: entity.PolicyEffectAllow, Actions: []entity.PolicyAction{entity.PolicyActionRead},
	})
	env.policies.AssignRole("policy-payment-read", role)
	if err := env.serviceAccounts.GrantRole(t.Context(), &entity.ServiceAccountRole{ServiceAccountID: serviceAccountID, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	createValidSecret(t, env, "prod/payment/database")
	createValidSecret(t, env, "prod/hr/database")

	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{
		OrganizationID: testOrgID, Path: "prod/payment/database", ActorUserID: serviceAccountID, ActorIsServiceAccount: true,
	}); err != nil {
		t.Errorf("GetSecret(prod/payment/database) by payment-service = %v, want nil (ALLOW per the objective's own worked example)", err)
	}
	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{
		OrganizationID: testOrgID, Path: "prod/hr/database", ActorUserID: serviceAccountID, ActorIsServiceAccount: true,
	}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret(prod/hr/database) by payment-service = %v, want entity.ErrForbidden (DENY — outside its granted path)", err)
	}
}

// TestSecretService_ServiceAccountActor_NoPermissionDeniedEvenWithPolicy
// proves a service account's own global secrets:read permission (not just
// a path policy) is still checked first — the identical "permission, then
// policy, both required" ordering
// TestSecretService_PathPolicy_DeniesFullPathAccessWithoutPermission
// already proves for a human actor, here proven for a machine one so
// there is no way for a service account specifically to bypass the
// global-permission gate that a user actor cannot.
func TestSecretService_ServiceAccountActor_NoPermissionDeniedEvenWithPolicy(t *testing.T) {
	env := newTestSecretEnv(t)
	const serviceAccountID = "sa-no-permission"
	const role = "role-full-policy-no-perm"
	env.policies.GrantFullAccessToRole(role)
	if err := env.serviceAccounts.GrantRole(t.Context(), &entity.ServiceAccountRole{ServiceAccountID: serviceAccountID, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}
	createValidSecret(t, env, "app/db")

	_, err := env.svc.GetSecret(t.Context(), GetSecretInput{
		OrganizationID: testOrgID, Path: "app/db", ActorUserID: serviceAccountID, ActorIsServiceAccount: true,
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret() by a service account with a full-access policy but no secrets:read permission, error = %v, want entity.ErrForbidden", err)
	}
}

// TestSecretService_ServiceAccountActor_UserRoleGrantDoesNotLeakToServiceAccount
// proves role/policy resolution is genuinely isolated by identity type:
// granting a role to a *user* ID (user_roles) must never make a service
// account of the same ID string (a contrived but worth-proving collision)
// inherit that role's path-policy grants via service_account_roles — the
// dispatch in roleIDsForActor must key off actorIsServiceAccount, never
// merely off whether some row with this ID happens to exist in either
// table. (The two identities share a global secrets:read grant here only
// because FakeRBACRepository's own doc comment already explains it makes
// no user-vs-service-account distinction at that layer; the real
// Postgres-backed RBACRepository joins user_roles/service_account_roles
// separately even for that check — this test isolates the layer the fake
// *can* faithfully distinguish, role/policy resolution, which is exactly
// where Sprint 5 Task 1's actual bug risk was.)
func TestSecretService_ServiceAccountActor_UserRoleGrantDoesNotLeakToServiceAccount(t *testing.T) {
	env := newTestSecretEnv(t)
	const sharedID = "id-shared-across-tables"
	env.rbac.Grant(sharedID, permSecretsRead)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: sharedID, RoleID: testFullAccessRoleID}); err != nil {
		t.Fatalf("GrantRole(user): %v", err)
	}
	createValidSecret(t, env, "app/shared-id-db")

	// As a user, sharedID is fully authorized (permission + full-access policy).
	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{
		OrganizationID: testOrgID, Path: "app/shared-id-db", ActorUserID: sharedID, ActorIsServiceAccount: false,
	}); err != nil {
		t.Fatalf("GetSecret() as user sharedID = %v, want nil", err)
	}
	// The identical ID, presented as a service account, holds no
	// service_account_roles grant at all and must be denied — RBACRepository.
	// ServiceAccountHasPermission's own doc comment: the join is unrelated to
	// UserHasPermission's, so a permission that exists for one identity type
	// under this ID must never be visible to the other.
	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{
		OrganizationID: testOrgID, Path: "app/shared-id-db", ActorUserID: sharedID, ActorIsServiceAccount: true,
	}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetSecret() as service account sharedID = %v, want entity.ErrForbidden (must not inherit the user grant)", err)
	}
}

// =====================================================================
// Secret Versioning phase: ListVersions and RollbackSecret
// =====================================================================

// threeVersionSecret creates "app/versioned" and updates it twice, so the
// history is exactly version 1 = A, 2 = B, 3 = C — the same fixture every
// test below builds on, matching this phase's own worked example.
func threeVersionSecret(t *testing.T, env *testSecretEnv) SecretMetadata {
	t.Helper()
	meta, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", Payload: map[string]string{"value": "A"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	meta, err = env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"value": "B"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("UpdateSecret() (v2) error = %v", err)
	}
	meta, err = env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"value": "C"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("UpdateSecret() (v3) error = %v", err)
	}
	if meta.CurrentVersion != 3 {
		t.Fatalf("threeVersionSecret setup: CurrentVersion = %d, want 3", meta.CurrentVersion)
	}
	return meta
}

func valueAtVersion(t *testing.T, env *testSecretEnv, path string, version int) string {
	t.Helper()
	val, err := env.svc.GetSecret(t.Context(), GetSecretInput{
		OrganizationID: testOrgID, Path: path, Version: &version, ActorUserID: readerID,
	})
	if err != nil {
		t.Fatalf("GetSecret() version %d error = %v", version, err)
	}
	return val.Payload["value"]
}

// --- ListVersions: metadata for every version, current flagged correctly ---

func TestSecretService_ListVersions_ReturnsMetadataForEveryVersion(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	versions, err := env.svc.ListVersions(t.Context(), ListVersionsInput{
		OrganizationID: testOrgID, Path: "app/versioned", ActorUserID: readerID,
	})
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}
	if len(versions) != 3 {
		t.Fatalf("ListVersions() returned %d entries, want 3", len(versions))
	}
	// Newest first (repository.SecretRepository.ListVersions' own contract).
	wantVersions := []int{3, 2, 1}
	for i, v := range versions {
		if v.Version != wantVersions[i] {
			t.Errorf("versions[%d].Version = %d, want %d", i, v.Version, wantVersions[i])
		}
		wantCurrent := v.Version == 3
		if v.Current != wantCurrent {
			t.Errorf("versions[%d] (version %d) Current = %v, want %v", i, v.Version, v.Current, wantCurrent)
		}
		if v.CreatedBy != ownerID {
			t.Errorf("versions[%d].CreatedBy = %q, want %q", i, v.CreatedBy, ownerID)
		}
	}
}

func TestSecretService_ListVersions_WithoutSecretsRead_Forbidden(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	_, err := env.svc.ListVersions(t.Context(), ListVersionsInput{
		OrganizationID: testOrgID, Path: "app/versioned", ActorUserID: nobodyID,
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("ListVersions() without secrets:read, error = %v, want entity.ErrForbidden", err)
	}
}

// --- RollbackSecret: creates version N+1 from a historical value, never
// deletes or overwrites anything ---

func TestSecretService_RollbackSecret_CreatesNewVersionWithTargetValue(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	meta, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", TargetVersion: 1, ExpectedVersion: 3, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("RollbackSecret() error = %v", err)
	}
	if meta.CurrentVersion != 4 {
		t.Errorf("RollbackSecret() CurrentVersion = %d, want 4", meta.CurrentVersion)
	}
	if got := valueAtVersion(t, env, "app/versioned", 4); got != "A" {
		t.Errorf("version 4 value = %q, want %q (version 1's value)", got, "A")
	}
}

func TestSecretService_RollbackSecret_PreservesAllHistoricalVersions(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	if _, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", TargetVersion: 1, ExpectedVersion: 3, ActorUserID: ownerID,
	}); err != nil {
		t.Fatalf("RollbackSecret() error = %v", err)
	}

	want := map[int]string{1: "A", 2: "B", 3: "C", 4: "A"}
	for version, wantValue := range want {
		if got := valueAtVersion(t, env, "app/versioned", version); got != wantValue {
			t.Errorf("version %d value = %q, want %q — rollback must never mutate an existing version", version, got, wantValue)
		}
	}

	versions, err := env.svc.ListVersions(t.Context(), ListVersionsInput{
		OrganizationID: testOrgID, Path: "app/versioned", ActorUserID: readerID,
	})
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}
	if len(versions) != 4 {
		t.Fatalf("ListVersions() after rollback returned %d entries, want 4 (1, 2, 3, 4 — nothing destroyed)", len(versions))
	}
	for _, v := range versions {
		wantCurrent := v.Version == 4
		if v.Current != wantCurrent {
			t.Errorf("version %d Current = %v, want %v", v.Version, v.Current, wantCurrent)
		}
	}
}

// --- Rollback authorization: read != rollback, update != rollback ---

func TestSecretService_RollbackSecret_WithoutSecretsRollback_Forbidden(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	// updaterID holds secrets:read AND secrets:update — a real, otherwise
	// fully-privileged secret writer — and must still be denied: this is
	// the test that actually proves permSecretsRollback is checked, not
	// just declared.
	_, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", TargetVersion: 1, ExpectedVersion: 3, ActorUserID: updaterID,
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("RollbackSecret() as a secrets:update (but not secrets:rollback) holder, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretService_RollbackSecret_ReaderOnly_Forbidden(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	_, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", TargetVersion: 1, ExpectedVersion: 3, ActorUserID: readerID,
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("RollbackSecret() as secrets:read-only, error = %v, want entity.ErrForbidden", err)
	}
}

// --- Rollback against a version that does not exist ---

func TestSecretService_RollbackSecret_NonexistentVersion_NotFound(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	_, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", TargetVersion: 99, ExpectedVersion: 3, ActorUserID: ownerID,
	})
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("RollbackSecret() to a nonexistent version, error = %v, want entity.ErrNotFound", err)
	}
}

// --- Concurrency: a rollback racing an update must never produce two
// writers both becoming version 4 ---

func TestSecretService_RollbackSecret_ConcurrentWithUpdate_OnlyOneWins(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	var wg sync.WaitGroup
	var mu sync.Mutex
	successes, conflicts := 0, 0
	record := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			successes++
		case errors.Is(err, entity.ErrVersionConflict):
			conflicts++
		default:
			t.Errorf("unexpected error = %v", err)
		}
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
			OrganizationID: testOrgID, Path: "app/versioned", TargetVersion: 1, ExpectedVersion: 3, ActorUserID: ownerID,
		})
		record(err)
	}()
	go func() {
		defer wg.Done()
		_, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
			OrganizationID: testOrgID, Path: "app/versioned", ExpectedVersion: 3,
			Payload: map[string]string{"value": "D"}, ActorUserID: ownerID,
		})
		record(err)
	}()
	wg.Wait()

	if successes != 1 {
		t.Errorf("successes = %d, want exactly 1 — a rollback racing an update must not both land as version 4", successes)
	}
	if conflicts != 1 {
		t.Errorf("conflicts = %d, want exactly 1", conflicts)
	}

	final, err := env.repo.GetByPath(t.Context(), testOrgID, "app/versioned")
	if err != nil {
		t.Fatalf("GetByPath() error = %v", err)
	}
	if final.CurrentVersion != 4 {
		t.Errorf("final CurrentVersion = %d, want 4 (exactly one of the two writers)", final.CurrentVersion)
	}
	versions, err := env.svc.ListVersions(t.Context(), ListVersionsInput{OrganizationID: testOrgID, Path: "app/versioned", ActorUserID: readerID})
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}
	if len(versions) != 4 {
		t.Errorf("ListVersions() returned %d entries, want exactly 4 — never two competing version-4 rows", len(versions))
	}
}

// --- Audit: version_accessed distinguishes a historical read from an
// ordinary current-version read; version_rollback carries from/to ---

func TestSecretService_GetSecret_SpecificVersion_AuditsVersionAccessed(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/versioned", ActorUserID: readerID}); err != nil {
		t.Fatalf("GetSecret() (current) error = %v", err)
	}
	v1 := 1
	if _, err := env.svc.GetSecret(t.Context(), GetSecretInput{OrganizationID: testOrgID, Path: "app/versioned", Version: &v1, ActorUserID: readerID}); err != nil {
		t.Fatalf("GetSecret() (version 1) error = %v", err)
	}

	var sawRead, sawVersionAccessed bool
	for _, e := range env.audit.Entries {
		switch e.Action {
		case "secret.read":
			sawRead = true
		case "secret.version_accessed":
			sawVersionAccessed = true
			if v, _ := e.Metadata["version"].(int); v != 1 {
				t.Errorf("secret.version_accessed metadata[version] = %v, want 1", e.Metadata["version"])
			}
		}
	}
	if !sawRead {
		t.Error("no secret.read audit entry for the current-version GetSecret call")
	}
	if !sawVersionAccessed {
		t.Error("no secret.version_accessed audit entry for the explicit-version GetSecret call")
	}
}

func TestSecretService_RollbackSecret_AuditsFromAndToVersion(t *testing.T) {
	env := newTestSecretEnv(t)
	threeVersionSecret(t, env)

	if _, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "app/versioned", TargetVersion: 1, ExpectedVersion: 3, ActorUserID: ownerID,
	}); err != nil {
		t.Fatalf("RollbackSecret() error = %v", err)
	}

	var found bool
	for _, e := range env.audit.Entries {
		if e.Action != "secret.version_rollback" {
			continue
		}
		found = true
		if e.Result != entity.AuditResultSuccess {
			t.Errorf("secret.version_rollback Result = %v, want success", e.Result)
		}
		if from, _ := e.Metadata["from_version"].(int); from != 1 {
			t.Errorf("secret.version_rollback metadata[from_version] = %v, want 1", e.Metadata["from_version"])
		}
		if to, _ := e.Metadata["to_version"].(int); to != 4 {
			t.Errorf("secret.version_rollback metadata[to_version] = %v, want 4", e.Metadata["to_version"])
		}
	}
	if !found {
		t.Error("no secret.version_rollback audit entry recorded")
	}
}

// --- Security: rollback's re-encryption never leaks plaintext into
// audit metadata, and never stores the target version's ciphertext
// verbatim (it must be freshly sealed under the new version's own AAD) ---

func TestSecretService_RollbackSecret_NeverLeaksPlaintextOrReusesRawCiphertext(t *testing.T) {
	env := newTestSecretEnv(t)
	const marker = "THIS_IS_TEST_ROLLBACK_VALUE"

	meta, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "app/rollback-marker", Payload: map[string]string{"value": marker}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	if _, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "app/rollback-marker", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"value": marker + "-v2"}, ActorUserID: ownerID,
	}); err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
	if _, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "app/rollback-marker", TargetVersion: 1, ExpectedVersion: 2, ActorUserID: ownerID,
	}); err != nil {
		t.Fatalf("RollbackSecret() error = %v", err)
	}

	for _, e := range env.audit.Entries {
		encoded, err := json.Marshal(e.Metadata)
		if err != nil {
			t.Fatalf("marshaling audit metadata: %v", err)
		}
		if strings.Contains(string(encoded), marker) {
			t.Errorf("audit entry action=%q metadata contains the plaintext marker: %s", e.Action, encoded)
		}
	}

	secret, err := env.repo.GetByPath(t.Context(), testOrgID, "app/rollback-marker")
	if err != nil {
		t.Fatalf("GetByPath() error = %v", err)
	}
	v1, err := env.repo.GetVersion(t.Context(), secret.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion(1) error = %v", err)
	}
	v3, err := env.repo.GetVersion(t.Context(), secret.ID, 3) // the rollback-created version
	if err != nil {
		t.Fatalf("GetVersion(3) error = %v", err)
	}
	if string(v1.Ciphertext) == string(v3.Ciphertext) {
		t.Error("rollback stored version 1's ciphertext verbatim — every version must be independently, freshly encrypted (fresh nonce, version-bound AAD)")
	}
	if strings.Contains(string(v1.Ciphertext), marker) || strings.Contains(string(v3.Ciphertext), marker) {
		t.Error("stored ciphertext contains the plaintext marker in the clear")
	}
}

// =====================================================================
// Path-Based Secret Authorization phase: rollback as its own path-policy
// action, distinct from "update"
// =====================================================================

// TestSecretService_PathPolicy_UpdateGrantDoesNotImplyRollback is the
// test that actually proves entity.PolicyActionRollback is enforced, not
// merely declared: an actor who holds the global secrets:rollback
// permission (the RBAC-layer gate) AND a path policy granting "update" on
// dev/* — but that policy's rule does not name "rollback" — must still be
// denied rollback on dev/*, even though the identical actor can update
// that same path freely. Narrowing at the path-policy layer must hold
// even when the broader, global permission is present; the two layers
// are independent restrictions, not a permission that leaks upward once
// granted at either one.
func TestSecretService_PathPolicy_UpdateGrantDoesNotImplyRollback(t *testing.T) {
	env := newTestSecretEnv(t)
	const actor = "user-dev-updater-no-rollback"
	const role = "role-dev-update-only"
	env.rbac.Grant(actor, permSecretsRead)
	env.rbac.Grant(actor, permSecretsUpdate)
	env.rbac.Grant(actor, permSecretsRollback) // global permission present
	env.policies.SeedPolicy(&entity.SecretPolicy{ID: "policy-dev-update-only", Name: "dev-update-only"})
	env.policies.SeedRule("policy-dev-update-only", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{entity.PolicyActionRead, entity.PolicyActionUpdate}, // no PolicyActionRollback
	})
	env.policies.AssignRole("policy-dev-update-only", role)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: actor, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	meta, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "dev/rollback-scope", Payload: map[string]string{"value": "A"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	meta, err = env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "dev/rollback-scope", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"value": "B"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("UpdateSecret() (v2) error = %v", err)
	}

	// The path policy grants update — this must succeed.
	if _, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "dev/rollback-scope", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"value": "C"}, ActorUserID: actor,
	}); err != nil {
		t.Errorf("UpdateSecret() by update-only actor = %v, want nil (policy grants update)", err)
	}

	// The same actor, same path, same global secrets:rollback permission —
	// but the path policy's rule never named "rollback". Must be denied.
	if _, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "dev/rollback-scope", TargetVersion: 1, ExpectedVersion: 3, ActorUserID: actor,
	}); !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("RollbackSecret() by update-only (no rollback in path policy) actor = %v, want entity.ErrForbidden", err)
	}
}

// TestSecretService_PathPolicy_RollbackActionExplicitlyGranted is the
// positive counterpart: once a path policy's rule explicitly names
// PolicyActionRollback, the same shape of actor (global secrets:rollback
// + path-scoped role) can roll back that path — proving the new action
// is not just enforced as a denial but genuinely grantable too.
func TestSecretService_PathPolicy_RollbackActionExplicitlyGranted(t *testing.T) {
	env := newTestSecretEnv(t)
	const actor = "user-dev-rollback-granted"
	const role = "role-dev-rollback"
	env.rbac.Grant(actor, permSecretsRead)
	env.rbac.Grant(actor, permSecretsUpdate)
	env.rbac.Grant(actor, permSecretsRollback)
	env.policies.SeedPolicy(&entity.SecretPolicy{ID: "policy-dev-rollback", Name: "dev-rollback"})
	env.policies.SeedRule("policy-dev-rollback", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{entity.PolicyActionRead, entity.PolicyActionUpdate, entity.PolicyActionRollback},
	})
	env.policies.AssignRole("policy-dev-rollback", role)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: actor, RoleID: role}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	meta, err := env.svc.CreateSecret(t.Context(), CreateSecretInput{
		OrganizationID: testOrgID, Path: "dev/rollback-granted", Payload: map[string]string{"value": "A"}, ActorUserID: ownerID,
	})
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	if _, err := env.svc.UpdateSecret(t.Context(), UpdateSecretInput{
		OrganizationID: testOrgID, Path: "dev/rollback-granted", ExpectedVersion: meta.CurrentVersion,
		Payload: map[string]string{"value": "B"}, ActorUserID: ownerID,
	}); err != nil {
		t.Fatalf("UpdateSecret() (v2) error = %v", err)
	}

	if _, err := env.svc.RollbackSecret(t.Context(), RollbackSecretInput{
		OrganizationID: testOrgID, Path: "dev/rollback-granted", TargetVersion: 1, ExpectedVersion: 2, ActorUserID: actor,
	}); err != nil {
		t.Errorf("RollbackSecret() by actor whose policy explicitly grants rollback = %v, want nil", err)
	}
}
