//go:build integration

package integration

import (
	"context"
	"crypto/rand"
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

func (p *multiKeyTestProvider) GetCurrentKey(_ context.Context) ([]byte, string, error) {
	return p.keys[p.currentID], p.currentID, nil
}

func (p *multiKeyTestProvider) GetKey(_ context.Context, keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, secrets.ErrKeyNotFound
	}
	return key, nil
}

// TestKeyRotation_Simulation is Sprint 4 Task 1's rotation simulation,
// run against a real Postgres database end to end — the encryption_keys
// table (migrations/000026), secret_versions (migrations/000024), and the
// real internal/secrets.KeyManager + EncryptionService, no mocks:
//
//  1. key-v1 starts ACTIVE (KeyManager bootstrap).
//  2. secret-version-1 is created; its stored key_id is key-v1.
//  3. Rotate to key-v2: key-v2 becomes ACTIVE, key-v1 becomes RETIRING.
//  4. secret-version-2 is created; its stored key_id is key-v2.
//  5. Both versions remain independently decryptable — version 1 under
//     key-v1 (now retiring, not gone), version 2 under key-v2.
//  6. New encryption after rotation uses key-v2, never key-v1 again.
func TestKeyRotation_Simulation(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	user := seedSecretTestUser(t, db)

	provider := newMultiKeyTestProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	keyStore := postgres.NewKeyMetadataStore(db)
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

	// --- Verify: GetCurrentKey now resolves to key-v2, not key-v1 ---
	_, currentID, err := keyManager.GetCurrentKey(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKey() after rotation, error = %v", err)
	}
	if currentID != "key-v2" {
		t.Errorf("GetCurrentKey() after rotation returned key_id %q, want key-v2", currentID)
	}
}
