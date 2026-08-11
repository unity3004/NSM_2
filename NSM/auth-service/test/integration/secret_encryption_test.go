//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/secrets"
)

// newTestEncryptionService builds a secrets.EncryptionService backed by a
// DevKeyProvider seeded with a freshly generated, never-persisted-anywhere
// random test key — never a literal, never a real deployment's key.
func newTestEncryptionService(t *testing.T) *secrets.EncryptionService {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	provider, err := secrets.NewDevKeyProvider("integration-test-key-1", base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewDevKeyProvider: %v", err)
	}
	return secrets.NewEncryptionService(provider)
}

// TestSecretEncryption_RoundTripsThroughRealDatabase is Phase 2's
// verification that EncryptedPayload (internal/secrets) is compatible
// with secret_versions (Phase 1, migrations/000024): it encrypts a real
// plaintext, maps every EncryptedPayload field onto entity.SecretVersion,
// persists it through the real repository.SecretRepository.CreateVersion,
// reads it back from real Postgres, maps the read-back row back onto an
// EncryptedPayload, and decrypts it — proving the two phases' data shapes
// actually fit together, not just that they compile together.
func TestSecretEncryption_RoundTripsThroughRealDatabase(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secretRepo := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)
	enc := newTestEncryptionService(t)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-crypto/db/password", CreatedBy: user.ID}
	if err := secretRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create() secret error = %v", err)
	}

	const original = "correct-horse-battery-staple-42"
	ec := secrets.EncryptContext{SecretID: s.ID, Version: 1}
	payload, err := enc.Encrypt(ctx, []byte(original), ec)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Map EncryptedPayload -> entity.SecretVersion. This mapping is the
	// thing under test: every EncryptedPayload field must have a home on
	// entity.SecretVersion, and nothing required for decryption may be
	// dropped.
	v := &entity.SecretVersion{
		SecretID:   s.ID,
		Ciphertext: payload.Ciphertext,
		Nonce:      payload.Nonce,
		AuthTag:    payload.AuthTag,
		Algorithm:  payload.Algorithm,
		WrappedDEK: payload.WrappedDEK,
		KeyID:      payload.KeyID,
		CreatedBy:  user.ID,
	}
	if err := secretRepo.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}
	if v.Version != 1 {
		t.Fatalf("CreateVersion() Version = %d, want 1", v.Version)
	}

	// Read back from a clean query, not the in-memory struct just
	// written, so this genuinely proves round-tripping through Postgres
	// and not just through Go memory.
	stored, err := secretRepo.GetVersion(ctx, s.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}

	// Map entity.SecretVersion -> EncryptedPayload, the reverse direction
	// a future SecretService.GetSecretValue would perform.
	readBack := &secrets.EncryptedPayload{
		Ciphertext: stored.Ciphertext,
		Nonce:      stored.Nonce,
		AuthTag:    stored.AuthTag,
		WrappedDEK: stored.WrappedDEK,
		KeyID:      stored.KeyID,
		Algorithm:  stored.Algorithm,
	}
	got, err := enc.Decrypt(ctx, readBack, ec)
	if err != nil {
		t.Fatalf("Decrypt() of the round-tripped payload, error = %v", err)
	}
	if !bytes.Equal(got, []byte(original)) {
		t.Errorf("Decrypt() = %q, want %q", got, original)
	}
}

// TestSecretEncryption_MultipleVersions_EachIndependentlyDecryptable
// proves version 1 and version 2 of the same secret each decrypt
// correctly and independently — version 2 existing (and using a fresh DEK
// and nonce) must not affect version 1's own decryptability, and
// EncryptContext's Version binding must correctly distinguish them (a
// version-1 payload decrypted with Version:2 in the context must fail,
// even for the same SecretID).
func TestSecretEncryption_MultipleVersions_EachIndependentlyDecryptable(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secretRepo := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)
	enc := newTestEncryptionService(t)

	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-crypto/api/key", CreatedBy: user.ID}
	if err := secretRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create() secret error = %v", err)
	}

	plaintexts := []string{"first-value", "rotated-second-value"}
	for i, pt := range plaintexts {
		version := i + 1
		payload, err := enc.Encrypt(ctx, []byte(pt), secrets.EncryptContext{SecretID: s.ID, Version: version})
		if err != nil {
			t.Fatalf("Encrypt() version %d error = %v", version, err)
		}
		v := &entity.SecretVersion{
			SecretID: s.ID, Ciphertext: payload.Ciphertext, Nonce: payload.Nonce, AuthTag: payload.AuthTag,
			Algorithm: payload.Algorithm, WrappedDEK: payload.WrappedDEK, KeyID: payload.KeyID, CreatedBy: user.ID,
		}
		if err := secretRepo.CreateVersion(ctx, v); err != nil {
			t.Fatalf("CreateVersion() version %d error = %v", version, err)
		}
	}

	for i, want := range plaintexts {
		version := i + 1
		stored, err := secretRepo.GetVersion(ctx, s.ID, version)
		if err != nil {
			t.Fatalf("GetVersion(%d) error = %v", version, err)
		}
		payload := &secrets.EncryptedPayload{
			Ciphertext: stored.Ciphertext, Nonce: stored.Nonce, AuthTag: stored.AuthTag,
			WrappedDEK: stored.WrappedDEK, KeyID: stored.KeyID, Algorithm: stored.Algorithm,
		}
		got, err := enc.Decrypt(ctx, payload, secrets.EncryptContext{SecretID: s.ID, Version: version})
		if err != nil {
			t.Fatalf("Decrypt() version %d error = %v", version, err)
		}
		if string(got) != want {
			t.Errorf("Decrypt() version %d = %q, want %q", version, got, want)
		}
	}

	// Cross-version decryption must fail: version 1's stored payload,
	// decrypted with Version:2 in the AAD context.
	v1, err := secretRepo.GetVersion(ctx, s.ID, 1)
	if err != nil {
		t.Fatalf("GetVersion(1) error = %v", err)
	}
	payload := &secrets.EncryptedPayload{
		Ciphertext: v1.Ciphertext, Nonce: v1.Nonce, AuthTag: v1.AuthTag,
		WrappedDEK: v1.WrappedDEK, KeyID: v1.KeyID, Algorithm: v1.Algorithm,
	}
	if _, err := enc.Decrypt(ctx, payload, secrets.EncryptContext{SecretID: s.ID, Version: 2}); err == nil {
		t.Error("Decrypt() of version 1's payload using Version:2 in the context succeeded, want an authentication failure")
	}
}

// TestSecretEncryption_NoPlaintextInDatabase extends Phase 1's own
// plaintext-absence check (TestSecretVersion_NoPlaintextInDatabase in
// secret_repository_test.go, which used fake ciphertext because no
// encryption existed yet) now that real AES-256-GCM encryption exists:
// it stores a real encrypted payload and confirms the plaintext value
// never appears, in any form, anywhere in the raw row.
func TestSecretEncryption_NoPlaintextInDatabase(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	secretRepo := postgres.NewSecretRepository(db)
	user := seedSecretTestUser(t, db)
	enc := newTestEncryptionService(t)

	const plaintextMarker = "THIS_IS_TEST_SECRET_VALUE"
	s := &entity.Secret{OrganizationID: secretTestOrgID, Path: "app-crypto/security/plaintext-check", CreatedBy: user.ID}
	if err := secretRepo.Create(ctx, s); err != nil {
		t.Fatalf("Create() secret error = %v", err)
	}

	ec := secrets.EncryptContext{SecretID: s.ID, Version: 1}
	payload, err := enc.Encrypt(ctx, []byte(plaintextMarker), ec)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	v := &entity.SecretVersion{
		SecretID: s.ID, Ciphertext: payload.Ciphertext, Nonce: payload.Nonce, AuthTag: payload.AuthTag,
		Algorithm: payload.Algorithm, WrappedDEK: payload.WrappedDEK, KeyID: payload.KeyID, CreatedBy: user.ID,
	}
	if err := secretRepo.CreateVersion(ctx, v); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}

	var ciphertext, nonce, authTag, wrappedDEK []byte
	var algorithm, keyID, path string
	err = db.QueryRowContext(ctx, `
		SELECT sv.ciphertext, sv.nonce, sv.auth_tag, sv.wrapped_dek, sv.algorithm, sv.key_id, s.path
		FROM secret_versions sv JOIN secrets s ON s.id = sv.secret_id
		WHERE sv.id = $1`, v.ID,
	).Scan(&ciphertext, &nonce, &authTag, &wrappedDEK, &algorithm, &keyID, &path)
	if err != nil {
		t.Fatalf("re-reading inserted row: %v", err)
	}

	for name, val := range map[string]string{
		"ciphertext":  string(ciphertext),
		"nonce":       string(nonce),
		"auth_tag":    string(authTag),
		"wrapped_dek": string(wrappedDEK),
		"algorithm":   algorithm,
		"key_id":      keyID,
		"path":        path,
	} {
		if strings.Contains(val, plaintextMarker) {
			t.Errorf("column %q contains the plaintext test marker %q — real AES-256-GCM ciphertext must never contain the plaintext it encrypts", name, plaintextMarker)
		}
	}

	// Confirm this genuinely was encrypted, not merely stored as-is: the
	// ciphertext bytes must differ from the plaintext bytes.
	if bytes.Equal(ciphertext, []byte(plaintextMarker)) {
		t.Error("stored ciphertext is byte-for-byte identical to the plaintext — encryption did not occur")
	}
}
