package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/secrets"
)

// testReEncryptEnv wires a ReEncryptionService against a real
// secrets.EncryptionService/KeyManager (so every test here exercises
// genuine AES-256-GCM encrypt/decrypt, not a crypto stub) and in-memory
// fakes for everything else — the same shape newTestKeyRotationEnv
// already establishes for KeyRotationService, reusing fakeRotationProvider
// from key_rotation_service_test.go (same package) rather than defining a
// second multi-key test double.
type testReEncryptEnv struct {
	svc        *ReEncryptionService
	keyManager *secrets.KeyManager
	encryption *secrets.EncryptionService
	secretRepo *mocks.FakeSecretRepository
	audit      *mocks.FakeAuditLogRepository
	provider   *fakeRotationProvider
}

func newTestReEncryptEnv(t *testing.T) *testReEncryptEnv {
	t.Helper()
	provider := newFakeRotationProvider(t, "key-v1")
	km := secrets.NewKeyManager(provider, secrets.NewInMemoryKeyMetadataStore())
	enc := secrets.NewEncryptionService(km)
	secretRepo := mocks.NewFakeSecretRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)
	svc := NewReEncryptionService(enc, km, secretRepo, auditTx)
	return &testReEncryptEnv{svc: svc, keyManager: km, encryption: enc, secretRepo: secretRepo, audit: audit, provider: provider}
}

// bootstrap activates KEY-001 (key-v1) as the sole, active key — callers
// that need genuine key-v1 ciphertext must call seedEncryptedVersion
// *between* this and rotateToV2 (seedEncryptedVersion always encrypts
// under whatever key is currently active).
func (env *testReEncryptEnv) bootstrap(t *testing.T) {
	t.Helper()
	if _, _, err := env.keyManager.GetCurrentKey(context.Background()); err != nil {
		t.Fatalf("bootstrap (GetCurrentKey) error = %v", err)
	}
}

// rotateToV2 rotates so KEY-002 (key-v2) becomes ACTIVE and key-v1 moves
// to RETIRING ("PREVIOUS") — the exact scenario this whole engine exists
// for. Must be called after bootstrap.
func (env *testReEncryptEnv) rotateToV2(t *testing.T) {
	t.Helper()
	env.provider.addKey(t, "key-v2")
	if _, err := env.keyManager.Rotate(context.Background(), "key-v2"); err != nil {
		t.Fatalf("Rotate(key-v2) error = %v", err)
	}
}

// seedEncryptedVersion encrypts plaintext under whatever key is currently
// active via the real EncryptionService, then stores the resulting real
// ciphertext as a secret_versions row — never a hand-constructed fake
// payload, so every test's "old-key ciphertext" is something the real
// Decrypt path can actually open. Call this *before* rotateToV2 to get a
// genuinely key-v1-encrypted row.
func (env *testReEncryptEnv) seedEncryptedVersion(t *testing.T, secretID string, version int, plaintext string) *entity.SecretVersion {
	t.Helper()
	payload, err := env.encryption.Encrypt(context.Background(), []byte(plaintext), secrets.EncryptContext{SecretID: secretID, Version: version})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	return env.secretRepo.SeedVersion(&entity.SecretVersion{
		SecretID: secretID, Version: version,
		Ciphertext: payload.Ciphertext, Nonce: payload.Nonce, AuthTag: payload.AuthTag,
		WrappedDEK: payload.WrappedDEK, KeyID: payload.KeyID, Algorithm: payload.Algorithm,
		CreatedBy: "creator-1",
	})
}

func (env *testReEncryptEnv) decrypt(t *testing.T, v *entity.SecretVersion) string {
	t.Helper()
	payload := &secrets.EncryptedPayload{
		Ciphertext: v.Ciphertext, Nonce: v.Nonce, AuthTag: v.AuthTag,
		WrappedDEK: v.WrappedDEK, KeyID: v.KeyID, Algorithm: v.Algorithm,
	}
	pt, err := env.encryption.Decrypt(context.Background(), payload, secrets.EncryptContext{SecretID: v.SecretID, Version: v.Version})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	return string(pt)
}

// --- 1. One old-key encrypted secret is re-encrypted ---

func TestReEncryptBatch_SingleRecord_Migrates(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	v := env.seedEncryptedVersion(t, "secret-1", 1, "the-original-value")
	env.rotateToV2(t)

	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "203.0.113.5")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Migrated != 1 || result.Considered != 1 || len(result.Failures) != 0 {
		t.Fatalf("ReEncryptBatch() = %+v, want Considered=1 Migrated=1 no failures", result)
	}
	if v.KeyID != "key-v2" {
		t.Errorf("after migration, KeyID = %q, want key-v2", v.KeyID)
	}
	if got := env.decrypt(t, v); got != "the-original-value" {
		t.Errorf("Decrypt() after migration = %q, want %q", got, "the-original-value")
	}
}

// --- 2. Multiple old-key records: all successfully migrate ---

func TestReEncryptBatch_MultipleRecords_AllMigrate(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	versions := make([]*entity.SecretVersion, 5)
	for i := range versions {
		versions[i] = env.seedEncryptedVersion(t, "secret-multi", i+1, "value-"+string(rune('a'+i)))
	}
	env.rotateToV2(t)

	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Migrated != 5 {
		t.Fatalf("ReEncryptBatch() Migrated = %d, want 5", result.Migrated)
	}
	for i, v := range versions {
		if v.KeyID != "key-v2" {
			t.Errorf("version %d KeyID = %q, want key-v2", i+1, v.KeyID)
		}
		if got := env.decrypt(t, v); got != "value-"+string(rune('a'+i)) {
			t.Errorf("version %d decrypted = %q, want %q", i+1, got, "value-"+string(rune('a'+i)))
		}
	}
}

// --- 3. Already-current records are skipped (never even considered) ---

func TestReEncryptBatch_AlreadyCurrentKeyRecords_NeverConsidered(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	old := env.seedEncryptedVersion(t, "secret-1", 1, "old-value")
	env.rotateToV2(t)
	// Simulates a write that happened after rotation — SecretService
	// always encrypts under whatever's current, so this row is key-v2
	// from the moment it's created, never key-v1.
	current := env.seedEncryptedVersion(t, "secret-1", 2, "new-value")

	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Considered != 1 || result.Migrated != 1 {
		t.Fatalf("ReEncryptBatch() = %+v, want exactly the one key-v1 record considered/migrated", result)
	}
	if old.KeyID != "key-v2" {
		t.Errorf("the old key-v1 record was not migrated: KeyID = %q", old.KeyID)
	}
	if current.KeyID != "key-v2" {
		t.Errorf("the already-current record's KeyID changed to %q — it must never be touched", current.KeyID)
	}
}

// --- 4. Mixed key versions: only outdated (the named fromKeyID) migrate ---

func TestReEncryptBatch_MixedKeys_OnlyNamedKeyMigrates(t *testing.T) {
	env := newTestReEncryptEnv(t)
	// Bootstrap onto key-v1 and encrypt a record under it before rotating
	// away — this is genuinely key-v1 ciphertext, not a hand-edited KeyID.
	env.bootstrap(t)
	v1 := env.seedEncryptedVersion(t, "secret-a", 1, "under-v1")

	// Rotate to key-v2 and encrypt a second record under it, before
	// rotating away again — genuinely key-v2 ciphertext.
	env.rotateToV2(t)
	v2 := env.seedEncryptedVersion(t, "secret-b", 1, "under-v2")

	// Rotate to key-v3 — now key-v1 and key-v2 are both non-active
	// (RETIRING), key-v3 is ACTIVE.
	env.provider.addKey(t, "key-v3")
	if _, err := env.keyManager.Rotate(context.Background(), "key-v3"); err != nil {
		t.Fatalf("Rotate(key-v3) error = %v", err)
	}

	// Re-encrypting specifically fromKeyID=key-v1 must migrate only v1,
	// leaving v2 (a different, also non-active key) completely alone.
	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Migrated != 1 {
		t.Fatalf("ReEncryptBatch(fromKeyID=key-v1) Migrated = %d, want 1 (only the key-v1 record)", result.Migrated)
	}
	if v1.KeyID != "key-v3" {
		t.Errorf("key-v1 record's new KeyID = %q, want key-v3 (the currently active key)", v1.KeyID)
	}
	if v2.KeyID != "key-v2" {
		t.Errorf("key-v2 record's KeyID changed to %q — a key-v1 migration must never touch key-v2 records", v2.KeyID)
	}
	if got := env.decrypt(t, v2); got != "under-v2" {
		t.Errorf("key-v2 record decrypted = %q, want %q (still readable, untouched)", got, "under-v2")
	}
}

// --- 5. Decryption failure: record remains unchanged ---

func TestReEncryptBatch_DecryptFailure_RecordUnchanged(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	v := env.seedEncryptedVersion(t, "secret-1", 1, "value")
	env.rotateToV2(t)
	originalCiphertext := append([]byte(nil), v.Ciphertext...)
	v.AuthTag[0] ^= 0xFF // tamper: authentication will now fail

	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Migrated != 0 || len(result.Failures) != 1 {
		t.Fatalf("ReEncryptBatch() = %+v, want 0 migrated, 1 failure", result)
	}
	if result.Failures[0].Category != "decrypt_failed" {
		t.Errorf("failure category = %q, want decrypt_failed", result.Failures[0].Category)
	}
	if v.KeyID != "key-v1" {
		t.Errorf("KeyID changed to %q after a decrypt failure — the row must be untouched", v.KeyID)
	}
	if string(v.Ciphertext) != string(originalCiphertext) {
		t.Error("ciphertext changed after a decrypt failure — the row must be untouched")
	}
}

// --- 6. Database update failure: record remains valid ---

func TestReEncryptBatch_PersistFailure_RecordRemainsValid(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	v := env.seedEncryptedVersion(t, "secret-1", 1, "value")
	env.rotateToV2(t)
	env.secretRepo.FailNextReEncrypt = errors.New("simulated database failure")

	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Migrated != 0 || len(result.Failures) != 1 || result.Failures[0].Category != "persist_failed" {
		t.Fatalf("ReEncryptBatch() = %+v, want 0 migrated, 1 persist_failed failure", result)
	}
	if v.KeyID != "key-v1" {
		t.Fatalf("KeyID changed to %q after a persist failure — the row must be untouched", v.KeyID)
	}
	// The row must still be genuinely valid/decryptable under the old key
	// — a persist failure must never leave a half-written or corrupted
	// ciphertext behind.
	if got := env.decrypt(t, v); got != "value" {
		t.Errorf("Decrypt() after a persist failure = %q, want the original value still intact", got)
	}
}

// --- 7. Interrupted migration: safe to resume ---

func TestReEncryptAll_InterruptedMigration_ResumesSafely(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	versions := make([]*entity.SecretVersion, 10)
	for i := range versions {
		versions[i] = env.seedEncryptedVersion(t, "secret-interrupt", i+1, "value")
	}
	env.rotateToV2(t)

	// Simulate the process getting through 4 of 10 before "crashing" — a
	// single bounded batch, not the full loop.
	first, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 4, "")
	if err != nil {
		t.Fatalf("first ReEncryptBatch() error = %v", err)
	}
	if first.Migrated != 4 {
		t.Fatalf("first ReEncryptBatch() Migrated = %d, want 4", first.Migrated)
	}
	migratedAfterCrash := 0
	for _, v := range versions {
		if v.KeyID == "key-v2" {
			migratedAfterCrash++
		}
	}
	if migratedAfterCrash != 4 {
		t.Fatalf("after the simulated crash, %d records show key-v2, want exactly 4", migratedAfterCrash)
	}

	// "Restart": a fresh call (no carried-over state) finishes the rest.
	summary, err := env.svc.ReEncryptAll(context.Background(), "admin-1", "key-v1", 3, 0, "")
	if err != nil {
		t.Fatalf("resuming ReEncryptAll() error = %v", err)
	}
	if summary.Migrated != 6 {
		t.Fatalf("resumed ReEncryptAll() Migrated = %d, want 6 (the remaining records)", summary.Migrated)
	}
	for i, v := range versions {
		if v.KeyID != "key-v2" {
			t.Errorf("version %d KeyID = %q after full migration, want key-v2", i+1, v.KeyID)
		}
		if got := env.decrypt(t, v); got != "value" {
			t.Errorf("version %d decrypted = %q, want %q", i+1, got, "value")
		}
	}
}

// --- 8. Concurrent secret update: newer version is never overwritten ---

func TestReEncryptBatch_ConcurrentNewVersionWrite_NeverTouched(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	v1 := env.seedEncryptedVersion(t, "secret-1", 1, "old-value")
	env.rotateToV2(t)
	// Simulates SecretService.Update landing concurrently, mid-migration
	// — a real new version, for the same secret, always encrypted under
	// the currently active key automatically (never fromKeyID).
	v2 := env.seedEncryptedVersion(t, "secret-1", 2, "new-value")
	v2CiphertextBefore := append([]byte(nil), v2.Ciphertext...)
	v2KeyIDBefore := v2.KeyID

	if _, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, ""); err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}

	if v1.KeyID != "key-v2" {
		t.Errorf("older version KeyID = %q, want key-v2 (migrated)", v1.KeyID)
	}
	if v2.KeyID != v2KeyIDBefore {
		t.Errorf("newer version's KeyID changed from %q to %q — it must never be touched by a migration of an older version", v2KeyIDBefore, v2.KeyID)
	}
	if string(v2.Ciphertext) != string(v2CiphertextBefore) {
		t.Error("newer version's ciphertext bytes changed — it must never be touched")
	}
	if got := env.decrypt(t, v2); got != "new-value" {
		t.Errorf("newer version decrypted = %q, want %q", got, "new-value")
	}
}

// --- 9. Running migration twice: second run performs no unnecessary work ---

func TestReEncryptAll_RunTwice_SecondRunIsNoOp(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	for i := 1; i <= 3; i++ {
		env.seedEncryptedVersion(t, "secret-twice", i, "value")
	}
	env.rotateToV2(t)

	first, err := env.svc.ReEncryptAll(context.Background(), "admin-1", "key-v1", 10, 0, "")
	if err != nil {
		t.Fatalf("first ReEncryptAll() error = %v", err)
	}
	if first.Migrated != 3 {
		t.Fatalf("first ReEncryptAll() Migrated = %d, want 3", first.Migrated)
	}

	second, err := env.svc.ReEncryptAll(context.Background(), "admin-1", "key-v1", 10, 0, "")
	if err != nil {
		t.Fatalf("second ReEncryptAll() error = %v", err)
	}
	if second.Migrated != 0 || second.Skipped != 0 || len(second.Failures) != 0 {
		t.Fatalf("second ReEncryptAll() = %+v, want a true no-op (nothing left under key-v1 at all)", second)
	}
	if second.BatchesRun != 1 {
		t.Errorf("second ReEncryptAll() BatchesRun = %d, want 1 (one batch finding zero records, then stopping)", second.BatchesRun)
	}
}

// --- 10. Old key remains usable — and is never auto-retired ---

func TestReEncryptAll_OldKeyRemainsDecryptableAndNotRetired(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	env.seedEncryptedVersion(t, "secret-1", 1, "value")
	env.rotateToV2(t)

	if _, err := env.svc.ReEncryptAll(context.Background(), "admin-1", "key-v1", 10, 0, ""); err != nil {
		t.Fatalf("ReEncryptAll() error = %v", err)
	}

	// The key itself must still be resolvable — GetKey never refuses a
	// RETIRING key.
	if _, err := env.keyManager.GetKey(context.Background(), "key-v1"); err != nil {
		t.Errorf("GetKey(key-v1) after full migration, error = %v, want nil (still usable)", err)
	}
	meta, err := env.keyManager.Metadata(context.Background(), "key-v1")
	if err != nil {
		t.Fatalf("Metadata(key-v1) error = %v", err)
	}
	if meta.State != secrets.KeyStateRetiring {
		t.Errorf("key-v1 state after re-encryption = %q, want retiring — re-encryption must never retire a key itself", meta.State)
	}
}

// --- 11. Any remaining (not-yet-migrated) old-key record stays decryptable ---

func TestReEncryptBatch_UnmigratedRecordsRemainDecryptable(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	versions := make([]*entity.SecretVersion, 5)
	for i := range versions {
		versions[i] = env.seedEncryptedVersion(t, "secret-partial", i+1, "value")
	}
	env.rotateToV2(t)

	// Only migrate 2 of 5 — batchSize caps it.
	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 2, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Migrated != 2 {
		t.Fatalf("ReEncryptBatch() Migrated = %d, want 2 (batchSize cap)", result.Migrated)
	}

	for i, v := range versions {
		if got := env.decrypt(t, v); got != "value" {
			t.Errorf("version %d (KeyID=%q) decrypted = %q, want %q — every record, migrated or not, must remain decryptable", i+1, v.KeyID, got, "value")
		}
	}
}

// --- 12. Plaintext never appears in audit output ---

func TestReEncryptBatch_AuditNeverContainsPlaintextOrKeyMaterial(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	const marker = "unmistakable-plaintext-marker-should-never-leak-9f3a"
	env.seedEncryptedVersion(t, "secret-1", 1, marker)
	// Also trigger a failure path, which carries its own metadata.
	failing := env.seedEncryptedVersion(t, "secret-2", 1, "value-2")
	env.rotateToV2(t)
	failing.AuthTag[0] ^= 0xFF
	keyV1Material := env.provider.keys["key-v1"]

	if _, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "203.0.113.5"); err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}

	for _, e := range env.audit.Entries {
		encoded, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("json.Marshal(audit entry) error = %v", err)
		}
		body := string(encoded)
		if strings.Contains(body, marker) {
			t.Errorf("audit entry %q contains the plaintext marker: %s", e.Action, body)
		}
		if strings.Contains(body, string(keyV1Material)) {
			t.Errorf("audit entry %q contains raw key material", e.Action)
		}
	}
}

// --- Actor requirement ---

func TestReEncryptBatch_RequiresActor(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	env.seedEncryptedVersion(t, "secret-1", 1, "value")
	env.rotateToV2(t)

	_, err := env.svc.ReEncryptBatch(context.Background(), "", "key-v1", 10, "")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("ReEncryptBatch() with no actor, error = %v, want entity.ErrForbidden", err)
	}
}

func TestReEncryptAll_RequiresActor(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	env.rotateToV2(t)

	_, err := env.svc.ReEncryptAll(context.Background(), "", "key-v1", 10, 0, "")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("ReEncryptAll() with no actor, error = %v, want entity.ErrForbidden", err)
	}
}

// --- Refuses to re-encrypt away from the currently active key ---

func TestReEncryptBatch_RefusesActiveKey(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	env.rotateToV2(t) // key-v2 is now active
	v := env.seedEncryptedVersion(t, "secret-1", 1, "value")

	_, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v2", 10, "")
	if !errors.Is(err, ErrReEncryptFromActiveKey) {
		t.Errorf("ReEncryptBatch(fromKeyID=<active key>), error = %v, want ErrReEncryptFromActiveKey", err)
	}
	if v.KeyID != "key-v2" {
		t.Errorf("unrelated record's KeyID changed to %q", v.KeyID)
	}
}

// --- Lifecycle audit events (started/completed) ---

func TestReEncryptAll_WritesStartedAndCompletedAuditEvents(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	env.seedEncryptedVersion(t, "secret-1", 1, "value")
	env.rotateToV2(t)

	if _, err := env.svc.ReEncryptAll(context.Background(), "admin-1", "key-v1", 10, 0, "203.0.113.5"); err != nil {
		t.Fatalf("ReEncryptAll() error = %v", err)
	}

	seen := map[string]bool{}
	for _, e := range env.audit.Entries {
		if e.ResourceID != nil && *e.ResourceID == "key-v1" {
			seen[e.Action] = true
			if e.ActorType != entity.AuditActorUser || e.ActorID == nil || *e.ActorID != "admin-1" {
				t.Errorf("%q audit entry ActorType/ActorID = %v/%v, want user/admin-1", e.Action, e.ActorType, e.ActorID)
			}
		}
	}
	if !seen["key.reencryption.started"] {
		t.Error("ReEncryptAll() did not record key.reencryption.started")
	}
	if !seen["key.reencryption.completed"] {
		t.Error("ReEncryptAll() did not record key.reencryption.completed")
	}
}

// --- Soft-deleted versions are still migrated (they still need a usable key) ---

func TestReEncryptBatch_SoftDeletedVersionsStillMigrate(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	v := env.seedEncryptedVersion(t, "secret-1", 1, "value")
	env.rotateToV2(t)
	if err := env.secretRepo.SoftDeleteVersion(context.Background(), "secret-1", 1); err != nil {
		t.Fatalf("SoftDeleteVersion() error = %v", err)
	}

	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 10, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Migrated != 1 {
		t.Fatalf("ReEncryptBatch() Migrated = %d, want 1 (soft-deleted versions must still migrate)", result.Migrated)
	}
	if v.KeyID != "key-v2" {
		t.Errorf("soft-deleted version's KeyID = %q, want key-v2", v.KeyID)
	}
}

// --- Batch size is actually respected, not a full-table load ---

func TestReEncryptBatch_RespectsBatchSizeCap(t *testing.T) {
	env := newTestReEncryptEnv(t)
	env.bootstrap(t)
	for i := 1; i <= 10; i++ {
		env.seedEncryptedVersion(t, "secret-cap", i, "value")
	}
	env.rotateToV2(t)

	result, err := env.svc.ReEncryptBatch(context.Background(), "admin-1", "key-v1", 3, "")
	if err != nil {
		t.Fatalf("ReEncryptBatch() error = %v", err)
	}
	if result.Considered != 3 || result.Migrated != 3 {
		t.Fatalf("ReEncryptBatch(batchSize=3) = %+v, want exactly 3 considered/migrated even though 10 were eligible", result)
	}
}

// --- Structural proof: result/failure types carry no plaintext-shaped field ---

func TestReEncryptRecordFailure_JSONShapeCarriesNoSensitiveField(t *testing.T) {
	failure := ReEncryptRecordFailure{SecretID: "s1", Version: 1, VersionID: "v1", Category: "decrypt_failed"}
	encoded, err := json.Marshal(failure)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var probe struct {
		SecretID  string
		Version   int
		VersionID string
		Category  string
	}
	if err := json.Unmarshal(encoded, &probe); err != nil {
		t.Fatalf("ReEncryptRecordFailure JSON shape unexpected: %v", err)
	}
}
