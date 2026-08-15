//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/secrets"
)

// multiKeyTestProvider is a secrets.KeyProvider test double that can hold
// several keys — DevKeyProvider (internal/secrets/key_provider.go) is
// deliberately single-key-only, so this rotation simulation, like
// internal/secrets/key_manager_test.go's unit tests, needs something that
// can actually be rotated between. currentID is only used the very first
// time this provider is ever asked for a key (KeyManager's bootstrap) —
// every subsequent "which key is current" decision is KeyManager's own,
// resolved against the real encryption_keys table, never this provider.
type multiKeyTestProvider struct {
	currentID string
	keys      map[string][]byte
}

func newMultiKeyTestProvider(t *testing.T, currentID string) *multiKeyTestProvider {
	t.Helper()
	p := &multiKeyTestProvider{currentID: currentID, keys: map[string][]byte{}}
	p.addKey(t, currentID)
	return p
}

func (p *multiKeyTestProvider) addKey(t *testing.T, keyID string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	p.keys[keyID] = key
}

func (p *multiKeyTestProvider) GetCurrentKey(ctx context.Context) ([]byte, string, error) {
	key, err := p.GetKey(ctx, p.currentID)
	return key, p.currentID, err
}

// GetKey returns a fresh copy of the stored key material, never the map's
// own backing array — EncryptionService.Encrypt/Decrypt both deliberately
// zero() whatever a KeyProvider hands back once they're done with it (see
// encryption.go's own doc comment on that best-effort scrubbing). Handing
// out an aliased slice here would let that zeroing silently corrupt this
// provider's own stored key the first time it's used, exactly the bug
// DevKeyProvider.copyKey() exists to prevent for the real implementation.
func (p *multiKeyTestProvider) GetKey(_ context.Context, keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, secrets.ErrKeyNotFound
	}
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

// TestKeyRotation_Simulation is Sprint 4 Task 1's rotation simulation,
// run against a real Postgres database for the secret-storage half of the
// lifecycle — secrets/secret_versions (migrations/000024), the real
// repository.SecretRepository, and the real internal/secrets.KeyManager +
// EncryptionService, no mocks there. Key *metadata* bookkeeping, though,
// deliberately uses secrets.NewInMemoryKeyMetadataStore() rather than
// postgres.NewKeyMetadataStore(db) — a real, confirmed hazard, not just a
// test-isolation nicety: encryption_keys (migrations/000026) is
// platform-wide, not per-organization or per-test (see that migration's
// own doc comment — a real production deployment has exactly one
// KeyProvider/KeyManager for the whole process). In this shared dev
// database, the actual running application has already bootstrapped its
// own real ACTIVE key into that same table before this test ever runs.
// KeyManager.ensureBootstrapped would find that real row, and
// KeyManager.Rotate's ActivateNewKey would retire it and activate this
// test's own "key-v1" in its place — genuinely breaking the live
// application's encryption (its next GetCurrentKey call would try to
// fetch "key-v1"'s material from its own DevKeyProvider, which has never
// heard of it) for as long as this test suite happens to run alongside
// it. InMemoryKeyMetadataStore (the same store internal/secrets/key_manager_test.go's
// own unit tests already use) gives this test a private, isolated view
// of key lifecycle state with zero risk to whatever else is connected to
// this database, while every other part of the simulation below is still
// exercised for real: real AES-256-GCM encryption, real envelope-DEK
// wrapping, real Postgres secret_versions storage and retrieval, real
// KeyManager rotation logic and state transitions.
//
//  1. key-v1 starts ACTIVE (KeyManager bootstrap).
//  2. secret-version-1 is created; its stored key_id is key-v1.
//  3. Rotate to key-v2: key-v2 becomes ACTIVE, key-v1 becomes RETIRING.
//  4. secret-version-2 is created; its stored key_id is key-v2.
//  5. Both versions remain independently decryptable — version 1 under
//     key-v1 (now retiring, not gone), version 2 under key-v2.
//  6. New encryption after rotation uses key-v2, never key-v1 again.
//  7. Neither plaintext value appears anywhere in the raw stored row.
func TestKeyRotation_Simulation(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	user := seedSecretTestUser(t, db)

	provider := newMultiKeyTestProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	keyStore := secrets.NewInMemoryKeyMetadataStore()
	keyManager := secrets.NewKeyManager(provider, keyStore)
	enc := secrets.NewEncryptionService(keyManager)
	secretRepo := postgres.NewSecretRepository(db)

	// --- Start: key-v1 ACTIVE ---
	if _, _, err := keyManager.GetCurrentKey(ctx); err != nil {
		t.Fatalf("bootstrap GetCurrentKey() error = %v", err)
	}
	active, err := keyManager.Metadata(ctx, "key-v1")
	if err != nil || active.State != secrets.KeyStateActive {
		t.Fatalf("after bootstrap, key-v1 metadata = %+v (err %v), want state=active", active, err)
	}

	// --- Create secret-version-1 -> key-v1 ---
	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-crypto/rotation/simulation", CreatedBy: user.ID}
	if err := secretRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create() secret error = %v", err)
	}
	payload1, err := enc.Encrypt(ctx, []byte("version-1-secret-value"), secrets.EncryptContext{SecretID: s.ID, Version: 1})
	if err != nil {
		t.Fatalf("Encrypt() version 1 error = %v", err)
	}
	if payload1.KeyID != "key-v1" {
		t.Fatalf("version 1 encrypted under key_id %q, want key-v1", payload1.KeyID)
	}
	v1 := &entity.SecretVersion{
		SecretID: s.ID, Ciphertext: payload1.Ciphertext, Nonce: payload1.Nonce, AuthTag: payload1.AuthTag,
		Algorithm: payload1.Algorithm, WrappedDEK: payload1.WrappedDEK, KeyID: payload1.KeyID, CreatedBy: user.ID,
	}
	if err := secretRepo.CreateVersion(ctx, v1); err != nil {
		t.Fatalf("CreateVersion() version 1 error = %v", err)
	}

	// --- Rotate: key-v2 ACTIVE, key-v1 RETIRING ---
	if _, err := keyManager.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	v1Meta, err := keyManager.Metadata(ctx, "key-v1")
	if err != nil || v1Meta.State != secrets.KeyStateRetiring {
		t.Fatalf("after rotation, key-v1 metadata = %+v (err %v), want state=retiring", v1Meta, err)
	}
	v2Meta, err := keyManager.Metadata(ctx, "key-v2")
	if err != nil || v2Meta.State != secrets.KeyStateActive {
		t.Fatalf("after rotation, key-v2 metadata = %+v (err %v), want state=active", v2Meta, err)
	}

	// --- Create secret-version-2 -> key-v2 ---
	payload2, err := enc.Encrypt(ctx, []byte("version-2-secret-value"), secrets.EncryptContext{SecretID: s.ID, Version: 2})
	if err != nil {
		t.Fatalf("Encrypt() version 2 error = %v", err)
	}
	if payload2.KeyID != "key-v2" {
		t.Fatalf("version 2 (created after rotation) encrypted under key_id %q, want key-v2", payload2.KeyID)
	}
	v2 := &entity.SecretVersion{
		SecretID: s.ID, Ciphertext: payload2.Ciphertext, Nonce: payload2.Nonce, AuthTag: payload2.AuthTag,
		Algorithm: payload2.Algorithm, WrappedDEK: payload2.WrappedDEK, KeyID: payload2.KeyID, CreatedBy: user.ID,
	}
	if err := secretRepo.CreateVersion(ctx, v2); err != nil {
		t.Fatalf("CreateVersion() version 2 error = %v", err)
	}

	// --- Verify: version-1 decrypts using key-v1, version-2 using key-v2 ---
	stored1, err := secretRepo.GetVersion(ctx, s.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion(1) error = %v", err)
	}
	if stored1.KeyID != "key-v1" {
		t.Fatalf("stored version 1 key_id = %q, want key-v1 (rotation must never rewrite existing rows)", stored1.KeyID)
	}
	got1, err := enc.Decrypt(ctx, &secrets.EncryptedPayload{
		Ciphertext: stored1.Ciphertext, Nonce: stored1.Nonce, AuthTag: stored1.AuthTag,
		WrappedDEK: stored1.WrappedDEK, KeyID: stored1.KeyID, Algorithm: stored1.Algorithm,
	}, secrets.EncryptContext{SecretID: s.ID, Version: 1})
	if err != nil {
		t.Fatalf("Decrypt() version 1 after rotation, error = %v, want nil (old data must remain readable)", err)
	}
	if string(got1) != "version-1-secret-value" {
		t.Errorf("Decrypt() version 1 = %q, want %q", got1, "version-1-secret-value")
	}

	stored2, err := secretRepo.GetVersion(ctx, s.ID, 2)
	if err != nil {
		t.Fatalf("GetVersion(2) error = %v", err)
	}
	if stored2.KeyID != "key-v2" {
		t.Fatalf("stored version 2 key_id = %q, want key-v2", stored2.KeyID)
	}
	got2, err := enc.Decrypt(ctx, &secrets.EncryptedPayload{
		Ciphertext: stored2.Ciphertext, Nonce: stored2.Nonce, AuthTag: stored2.AuthTag,
		WrappedDEK: stored2.WrappedDEK, KeyID: stored2.KeyID, Algorithm: stored2.Algorithm,
	}, secrets.EncryptContext{SecretID: s.ID, Version: 2})
	if err != nil {
		t.Fatalf("Decrypt() version 2, error = %v", err)
	}
	if string(got2) != "version-2-secret-value" {
		t.Errorf("Decrypt() version 2 = %q, want %q", got2, "version-2-secret-value")
	}

	// --- Verify: neither plaintext value appears in the raw stored row,
	// under either key — the objective's own "no plaintext secret values
	// being stored" requirement, checked directly against what rotation
	// actually wrote (TestSecretVersion_NoPlaintextInDatabase separately
	// covers the schema-level guarantee; this is the row-content half,
	// specific to this test's own two plaintexts and both key
	// generations). ---
	for _, plaintext := range []string{"version-1-secret-value", "version-2-secret-value"} {
		// encode(bytea, 'escape') renders the raw bytes as text (escaping
		// only non-printable ones) — unlike a plain ::text cast on a bytea
		// column, which Postgres always hex-encodes and so could never
		// contain a plaintext substring even if the check meant to catch
		// that it did.
		var rawCount int
		if err := db.QueryRowContext(ctx,
			`SELECT count(*) FROM secret_versions WHERE secret_id = $1 AND encode(ciphertext, 'escape') LIKE '%' || $2 || '%'`,
			s.ID, plaintext,
		).Scan(&rawCount); err != nil {
			t.Fatalf("checking raw ciphertext for plaintext leakage: %v", err)
		}
		if rawCount > 0 {
			t.Errorf("plaintext %q appears in raw stored ciphertext — encryption is not actually protecting this value", plaintext)
		}
	}
	if strings.Contains(string(stored1.Ciphertext), "version-1-secret-value") || strings.Contains(string(stored2.Ciphertext), "version-2-secret-value") {
		t.Error("plaintext appears verbatim in the decoded ciphertext bytes")
	}

	// --- Verify: GetCurrentKey now resolves to key-v2, not key-v1 ---
	_, currentID, err := keyManager.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey() after rotation, error = %v", err)
	}
	if currentID != "key-v2" {
		t.Errorf("GetCurrentKey() after rotation returned key_id %q, want key-v2", currentID)
	}
}
