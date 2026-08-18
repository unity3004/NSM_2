//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/secrets"
	"github.com/acme/auth-service/internal/service"
)

// TestReEncryption_FullLifecycle is this phase's own most important test:
// create secret -> encrypt under KEY-001 -> rotate (KEY-002 becomes
// active) -> the old secret still decrypts under KEY-001 -> re-encrypt ->
// the secret now uses KEY-002 -> decrypt again -> the original plaintext
// is returned. Every step below is real: real Postgres secret_versions
// storage (migrations/000024), the real repository.SecretRepository
// (including the new ListVersionsByKeyID/ReEncryptVersion this phase
// adds), the real secrets.KeyManager/EncryptionService, and the real
// service.ReEncryptionService — nothing here is a crypto or persistence
// stub. Key *metadata* bookkeeping uses secrets.NewInMemoryKeyMetadataStore()
// rather than the Postgres-backed store — see TestKeyRotation_Simulation's
// own doc comment (key_rotation_test.go) for exactly why that isolation
// is required in this shared dev database, unchanged reasoning here.
func TestReEncryption_FullLifecycle(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	user := seedSecretTestUser(t, db)

	provider := newMultiKeyTestProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	keyManager := secrets.NewKeyManager(provider, secrets.NewInMemoryKeyMetadataStore())
	enc := secrets.NewEncryptionService(keyManager)
	secretRepo := postgres.NewSecretRepository(db)
	reencryptSvc := service.NewReEncryptionService(enc, keyManager, secretRepo, nil)

	// --- create secret, encrypted under KEY-001 ---
	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-crypto/reencryption/lifecycle", CreatedBy: user.ID}
	if err := secretRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create() secret error = %v", err)
	}
	const originalPlaintext = "the-value-that-must-survive-rotation-and-reencryption"
	payload, err := enc.Encrypt(ctx, []byte(originalPlaintext), secrets.EncryptContext{SecretID: s.ID, Version: 1})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if payload.KeyID != "key-v1" {
		t.Fatalf("initial encryption used key_id %q, want key-v1", payload.KeyID)
	}
	v := &entity.SecretVersion{
		SecretID: s.ID, Ciphertext: payload.Ciphertext, Nonce: payload.Nonce, AuthTag: payload.AuthTag,
		Algorithm: payload.Algorithm, WrappedDEK: payload.WrappedDEK, KeyID: payload.KeyID, CreatedBy: user.ID,
	}
	if err := secretRepo.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	// --- rotate: KEY-002 becomes active, KEY-001 becomes PREVIOUS (RETIRING) ---
	if _, err := keyManager.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	activeAfterRotation, err := keyManager.ActiveMetadata(ctx)
	if err != nil || activeAfterRotation.KeyID != "key-v2" {
		t.Fatalf("after Rotate(), active key = %+v (err %v), want key-v2", activeAfterRotation, err)
	}

	// --- the old secret still decrypts, under KEY-001, before any re-encryption ---
	stored, err := secretRepo.GetVersion(ctx, s.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion() before re-encryption, error = %v", err)
	}
	if stored.KeyID != "key-v1" {
		t.Fatalf("stored version key_id = %q before re-encryption, want key-v1", stored.KeyID)
	}
	gotBefore, err := enc.Decrypt(ctx, &secrets.EncryptedPayload{
		Ciphertext: stored.Ciphertext, Nonce: stored.Nonce, AuthTag: stored.AuthTag,
		WrappedDEK: stored.WrappedDEK, KeyID: stored.KeyID, Algorithm: stored.Algorithm,
	}, secrets.EncryptContext{SecretID: s.ID, Version: 1})
	if err != nil {
		t.Fatalf("Decrypt() before re-encryption, error = %v, want nil (KEY-001 must remain available)", err)
	}
	if string(gotBefore) != originalPlaintext {
		t.Fatalf("Decrypt() before re-encryption = %q, want %q", gotBefore, originalPlaintext)
	}

	// --- re-encryption: KEY-001 -> KEY-002 ---
	summary, err := reencryptSvc.ReEncryptAll(ctx, user.ID, "key-v1", 10, 0, "203.0.113.5")
	if err != nil {
		t.Fatalf("ReEncryptAll() error = %v", err)
	}
	if summary.Migrated != 1 || len(summary.Failures) != 0 {
		t.Fatalf("ReEncryptAll() summary = %+v, want exactly 1 migrated, no failures", summary)
	}

	// --- the secret now uses KEY-002 ---
	stored, err = secretRepo.GetVersion(ctx, s.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion() after re-encryption, error = %v", err)
	}
	if stored.KeyID != "key-v2" {
		t.Fatalf("stored version key_id after re-encryption = %q, want key-v2", stored.KeyID)
	}

	// --- decrypt again: the original plaintext is returned, byte-for-byte ---
	gotAfter, err := enc.Decrypt(ctx, &secrets.EncryptedPayload{
		Ciphertext: stored.Ciphertext, Nonce: stored.Nonce, AuthTag: stored.AuthTag,
		WrappedDEK: stored.WrappedDEK, KeyID: stored.KeyID, Algorithm: stored.Algorithm,
	}, secrets.EncryptContext{SecretID: s.ID, Version: 1})
	if err != nil {
		t.Fatalf("Decrypt() after re-encryption, error = %v, want nil", err)
	}
	if string(gotAfter) != originalPlaintext {
		t.Fatalf("Decrypt() after re-encryption = %q, want %q (the original value must survive rotation AND re-encryption unchanged)", gotAfter, originalPlaintext)
	}

	// --- no plaintext ever appears in the raw stored row, at any point ---
	var rawCount int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM secret_versions WHERE secret_id = $1 AND encode(ciphertext, 'escape') LIKE '%' || $2 || '%'`,
		s.ID, originalPlaintext,
	).Scan(&rawCount); err != nil {
		t.Fatalf("checking raw ciphertext for plaintext leakage: %v", err)
	}
	if rawCount > 0 {
		t.Error("plaintext appears in the raw stored ciphertext after re-encryption")
	}

	// --- KEY-001 was never retired by re-encryption itself ---
	oldMeta, err := keyManager.Metadata(ctx, "key-v1")
	if err != nil {
		t.Fatalf("Metadata(key-v1) error = %v", err)
	}
	if oldMeta.State != secrets.KeyStateRetiring {
		t.Errorf("key-v1 state after re-encryption = %q, want retiring — re-encryption must never retire a key", oldMeta.State)
	}

	// --- running re-encryption again is a safe no-op ---
	second, err := reencryptSvc.ReEncryptAll(ctx, user.ID, "key-v1", 10, 0, "203.0.113.5")
	if err != nil {
		t.Fatalf("second ReEncryptAll() error = %v", err)
	}
	if second.Migrated != 0 {
		t.Errorf("second ReEncryptAll() Migrated = %d, want 0 (nothing left under key-v1)", second.Migrated)
	}
}

// TestSecretRepository_ListVersionsByKeyID_RealDatabase proves the actual
// SQL — WHERE key_id = $1 ORDER BY id LIMIT $2, backed by
// idx_secret_versions_key_id (migrations/000036) — against a real
// Postgres, not the in-memory fake unit tests otherwise exercise.
func TestSecretRepository_ListVersionsByKeyID_RealDatabase(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	user := seedSecretTestUser(t, db)
	secretRepo := postgres.NewSecretRepository(db)

	keyID := "list-by-key-test-" + user.ID
	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-crypto/list-versions/" + user.ID, CreatedBy: user.ID}
	if err := secretRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	v := &entity.SecretVersion{
		SecretID: s.ID, Ciphertext: []byte("ct"), Nonce: []byte("nonce123456"), AuthTag: []byte("tag1234567890ab"),
		Algorithm: "AES-256-GCM", WrappedDEK: []byte("wrapped-dek-bytes-0123456789"), KeyID: keyID, CreatedBy: user.ID,
	}
	if err := secretRepo.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	found, err := secretRepo.ListVersionsByKeyID(ctx, keyID, 10)
	if err != nil {
		t.Fatalf("ListVersionsByKeyID() error = %v", err)
	}
	if len(found) != 1 || found[0].ID != v.ID {
		t.Fatalf("ListVersionsByKeyID(%q) = %+v, want exactly the one seeded version", keyID, found)
	}

	none, err := secretRepo.ListVersionsByKeyID(ctx, "key-id-nobody-uses-"+user.ID, 10)
	if err != nil {
		t.Fatalf("ListVersionsByKeyID() for an unused key, error = %v", err)
	}
	if len(none) != 0 {
		t.Errorf("ListVersionsByKeyID() for an unused key = %d rows, want 0", len(none))
	}
}

// TestSecretRepository_ReEncryptVersion_RealDatabase proves the real
// compare-and-swap UPDATE — both the success path and the "already
// changed since read" no-op path — against real Postgres.
func TestSecretRepository_ReEncryptVersion_RealDatabase(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	user := seedSecretTestUser(t, db)
	secretRepo := postgres.NewSecretRepository(db)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-crypto/reencrypt-version/" + user.ID, CreatedBy: user.ID}
	if err := secretRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	v := &entity.SecretVersion{
		SecretID: s.ID, Ciphertext: []byte("old-ct"), Nonce: []byte("nonce123456"), AuthTag: []byte("tag1234567890ab"),
		Algorithm: "AES-256-GCM", WrappedDEK: []byte("wrapped-dek-bytes-0123456789"), KeyID: "rewrap-key-v1", CreatedBy: user.ID,
	}
	if err := secretRepo.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	newEnvelope := repository.ReEncryptedEnvelope{
		Ciphertext: []byte("new-ct"), Nonce: []byte("newnonce1234"), AuthTag: []byte("newtag1234567890"),
		WrappedDEK: []byte("new-wrapped-dek-bytes-012345"), KeyID: "rewrap-key-v2", Algorithm: "AES-256-GCM",
	}

	// Wrong expectedKeyID: no-op, never an error.
	updated, err := secretRepo.ReEncryptVersion(ctx, v.ID, newEnvelope, "not-the-real-key-id")
	if err != nil {
		t.Fatalf("ReEncryptVersion() with a wrong expectedKeyID, error = %v, want nil", err)
	}
	if updated {
		t.Fatal("ReEncryptVersion() with a wrong expectedKeyID reported updated=true — must be a no-op")
	}
	unchanged, err := secretRepo.GetVersion(ctx, s.ID, v.Version)
	if err != nil {
		t.Fatalf("GetVersion() after a refused ReEncryptVersion(), error = %v", err)
	}
	if unchanged.KeyID != "rewrap-key-v1" || string(unchanged.Ciphertext) != "old-ct" {
		t.Fatalf("row changed after a refused ReEncryptVersion(): %+v", unchanged)
	}

	// Correct expectedKeyID: succeeds.
	updated, err = secretRepo.ReEncryptVersion(ctx, v.ID, newEnvelope, "rewrap-key-v1")
	if err != nil {
		t.Fatalf("ReEncryptVersion() error = %v", err)
	}
	if !updated {
		t.Fatal("ReEncryptVersion() with the correct expectedKeyID reported updated=false")
	}
	changed, err := secretRepo.GetVersion(ctx, s.ID, v.Version)
	if err != nil {
		t.Fatalf("GetVersion() after ReEncryptVersion(), error = %v", err)
	}
	if changed.KeyID != "rewrap-key-v2" || string(changed.Ciphertext) != "new-ct" || string(changed.Nonce) != "newnonce1234" {
		t.Fatalf("row after ReEncryptVersion() = %+v, want the new envelope", changed)
	}
	if changed.Version != v.Version || changed.SecretID != v.SecretID || changed.CreatedBy != v.CreatedBy {
		t.Errorf("ReEncryptVersion() changed a non-envelope field: got %+v", changed)
	}

	// Idempotent: calling it again with the now-stale expectedKeyID
	// (the original key-v1) is a no-op, never an error and never a
	// second write.
	updatedAgain, err := secretRepo.ReEncryptVersion(ctx, v.ID, newEnvelope, "rewrap-key-v1")
	if err != nil {
		t.Fatalf("second ReEncryptVersion() error = %v", err)
	}
	if updatedAgain {
		t.Error("second ReEncryptVersion() with a now-stale expectedKeyID reported updated=true")
	}

	// Sanity: the ciphertext bytes genuinely never contain a
	// human-readable trace of anything sensitive-shaped (this test's own
	// fixture values are innocuous placeholders, but the point is the
	// mechanism, not this specific string).
	if strings.Contains(string(changed.Ciphertext), "old-ct") {
		t.Error("new ciphertext unexpectedly still contains the old ciphertext's bytes")
	}
}
