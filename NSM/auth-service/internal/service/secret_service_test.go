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
	svc   *SecretService
	repo  *mocks.FakeSecretRepository
	rbac  *mocks.FakeRBACRepository
	audit *mocks.FakeAuditLogRepository
	enc   *secrets.EncryptionService
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

// newTestSecretEnv wires a SecretService against in-memory fakes and a
// real secrets.EncryptionService (real AES-256-GCM, a freshly generated
// test-only key) — no database, real business logic, real cryptography.
// ownerID and readerID are pre-granted every secrets:* permission and
// secrets:read respectively; nobodyID is deliberately granted nothing.
func newTestSecretEnv(t *testing.T) *testSecretEnv {
	t.Helper()
	repo := mocks.NewFakeSecretRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := NewRBACService(rbacRepo)
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

	svc := NewSecretService(repo, enc, rbacSvc, auditTx)
	return &testSecretEnv{svc: svc, repo: repo, rbac: rbacRepo, audit: audit, enc: enc, rawKey: rawKey}
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
		otherSvc := NewSecretService(env.repo, secrets.NewEncryptionService(otherProvider), NewRBACService(env.rbac), nil)

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
		otherSvc := NewSecretService(env.repo, secrets.NewEncryptionService(otherProvider), NewRBACService(env.rbac), nil)

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
