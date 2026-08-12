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
)

// testSecretEnv is everything one test needs: a SecretService plus direct
// access to the fakes underneath it, so a test can inspect what was
// actually persisted/audited without going through the service's own
// (deliberately narrow) return types.
type testSecretEnv struct {
	svc       *SecretService
	repo      *mocks.FakeSecretRepository
	rbac      *mocks.FakeRBACRepository
	users     *mocks.FakeUserRepository
	policies  *mocks.FakeSecretPolicyRepository
	policySvc *SecretPolicyService
	audit     *mocks.FakeAuditLogRepository
	enc       *secrets.EncryptionService
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
	policySvc := NewSecretPolicyService(policyRepo, users, rbacSvc, nil)
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
	rbacRepo.Grant(readerID, permSecretsRead)

	policyRepo.GrantFullAccessToRole(testFullAccessRoleID)
	if err := users.GrantRole(t.Context(), &entity.UserRole{UserID: ownerID, RoleID: testFullAccessRoleID}); err != nil {
		t.Fatalf("GrantRole(owner): %v", err)
	}
	if err := users.GrantRole(t.Context(), &entity.UserRole{UserID: readerID, RoleID: testFullAccessRoleID}); err != nil {
		t.Fatalf("GrantRole(reader): %v", err)
	}

	svc := NewSecretService(repo, enc, rbacSvc, policySvc, auditTx)
	return &testSecretEnv{svc: svc, repo: repo, rbac: rbacRepo, users: users, policies: policyRepo, policySvc: policySvc, audit: audit, enc: enc, rawKey: rawKey}
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
