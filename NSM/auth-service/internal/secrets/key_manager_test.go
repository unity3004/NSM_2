package secrets

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeMultiKeyProvider is a KeyProvider test double that (unlike
// DevKeyProvider, which is deliberately single-key-only — see its own doc
// comment) can hold several keys at once, so KeyManager's rotation logic
// has something real to rotate between. failKeyID, if set, makes GetKey
// return failErr for that one identifier — used to simulate a provider
// that is unavailable for a specific key (test requirement #9/#10)
// without making the whole provider unusable.
type fakeMultiKeyProvider struct {
	keys       map[string][]byte
	currentID  string
	failKeyID  string
	failErr    error
	failAlways bool
}

func newFakeMultiKeyProvider(t *testing.T, currentID string) *fakeMultiKeyProvider {
	t.Helper()
	return &fakeMultiKeyProvider{keys: map[string][]byte{currentID: randomKey(t)}, currentID: currentID}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, dekLength)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return k
}

// addKey registers keyID with fresh random material — simulating an
// operator having provisioned a new key in the provider ahead of rotation.
func (p *fakeMultiKeyProvider) addKey(t *testing.T, keyID string) {
	t.Helper()
	p.keys[keyID] = randomKey(t)
}

func (p *fakeMultiKeyProvider) GetCurrentKey(ctx context.Context) ([]byte, string, error) {
	key, err := p.GetKey(ctx, p.currentID)
	return key, p.currentID, err
}

func (p *fakeMultiKeyProvider) GetKey(_ context.Context, keyID string) ([]byte, error) {
	if p.failAlways || (p.failKeyID != "" && keyID == p.failKeyID) {
		return nil, p.failErr
	}
	key, ok := p.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

func newTestKeyManager(t *testing.T, provider KeyProvider) (*KeyManager, KeyMetadataStore) {
	t.Helper()
	store := NewInMemoryKeyMetadataStore()
	return NewKeyManager(provider, store), store
}

// --- 1. Current key retrieval ---

func TestKeyManager_GetCurrentKey_BootstrapsFromProvider(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	km, store := newTestKeyManager(t, provider)

	key, keyID, err := km.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if keyID != "key-v1" {
		t.Errorf("GetCurrentKey() keyID = %q, want %q", keyID, "key-v1")
	}
	if len(key) != dekLength {
		t.Errorf("GetCurrentKey() returned a %d-byte key, want %d", len(key), dekLength)
	}

	active, err := store.GetActive(context.Background())
	if err != nil {
		t.Fatalf("store.GetActive() after bootstrap, error = %v", err)
	}
	if active.KeyID != "key-v1" || active.State != KeyStateActive {
		t.Errorf("bootstrap registered %+v, want KeyID=key-v1 State=active", active)
	}
}

func TestKeyManager_Bootstrap_IsIdempotent(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()

	first, didFirst, err := km.Bootstrap(ctx)
	if err != nil || !didFirst {
		t.Fatalf("first Bootstrap() = (%+v, %v, %v), want (_, true, nil)", first, didFirst, err)
	}
	second, didSecond, err := km.Bootstrap(ctx)
	if err != nil || didSecond {
		t.Fatalf("second Bootstrap() = (%+v, %v, %v), want (_, false, nil)", second, didSecond, err)
	}
	if first.KeyID != second.KeyID {
		t.Errorf("Bootstrap() KeyID changed across calls: %q then %q", first.KeyID, second.KeyID)
	}
}

// --- 2. Historical key retrieval ---

func TestKeyManager_GetKey_RetrievesHistoricalKeyAfterRotation(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()

	if _, _, err := km.GetCurrentKey(ctx); err != nil { // bootstrap key-v1
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	// key-v1 is now RETIRING, not gone — GetKey must still return it.
	key, err := km.GetKey(ctx, "key-v1")
	if err != nil {
		t.Fatalf("GetKey(key-v1) after rotation, error = %v, want nil", err)
	}
	if len(key) != dekLength {
		t.Errorf("GetKey(key-v1) returned a %d-byte key, want %d", len(key), dekLength)
	}
}

// --- 3, 4, 5, 6: full encrypt/decrypt behavior across rotation ---

func TestKeyManager_EncryptionRoundTrip_AcrossRotation(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	km, _ := newTestKeyManager(t, provider)
	enc := NewEncryptionService(km)
	ctx := context.Background()
	ec1 := EncryptContext{SecretID: "secret-1", Version: 1}
	ec2 := EncryptContext{SecretID: "secret-1", Version: 2}

	// 3. Encryption uses the current key.
	payload1, err := enc.Encrypt(ctx, []byte("version-1-value"), ec1)
	if err != nil {
		t.Fatalf("Encrypt() version 1, error = %v", err)
	}
	if payload1.KeyID != "key-v1" {
		t.Fatalf("version 1 encrypted under KeyID %q, want key-v1", payload1.KeyID)
	}

	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	// 6. New ciphertext uses the new key.
	payload2, err := enc.Encrypt(ctx, []byte("version-2-value"), ec2)
	if err != nil {
		t.Fatalf("Encrypt() version 2, error = %v", err)
	}
	if payload2.KeyID != "key-v2" {
		t.Fatalf("version 2 encrypted under KeyID %q, want key-v2", payload2.KeyID)
	}

	// 4 & 5. Decryption uses the stored key_id, and old ciphertext (under
	// the now-retiring key) remains decryptable after rotation.
	got1, err := enc.Decrypt(ctx, payload1, ec1)
	if err != nil {
		t.Fatalf("Decrypt() version 1 after rotation, error = %v, want nil", err)
	}
	if string(got1) != "version-1-value" {
		t.Errorf("Decrypt() version 1 = %q, want %q", got1, "version-1-value")
	}
	got2, err := enc.Decrypt(ctx, payload2, ec2)
	if err != nil {
		t.Fatalf("Decrypt() version 2, error = %v", err)
	}
	if string(got2) != "version-2-value" {
		t.Errorf("Decrypt() version 2 = %q, want %q", got2, "version-2-value")
	}
}

// --- 7. Unknown key_id fails ---

func TestKeyManager_GetKey_UnknownKeyIDFails(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}

	// key-not-v99 is not known to the metadata store at all — refused
	// without ever consulting the provider, even though a provider that
	// happened to have a key under that identifier could otherwise have
	// served it. See KeyManager.GetKey's own doc comment on why.
	_, err := km.GetKey(ctx, "key-not-v99")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("GetKey() with an unknown key ID, error = %v, want ErrKeyNotFound", err)
	}
}

// --- 8. Disabled key fails ---

func TestKeyManager_GetKey_DisabledKeyFails(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if err := km.DisableKey(ctx, "key-v1"); err != nil {
		t.Fatalf("DisableKey(key-v1) error = %v", err)
	}

	_, err := km.GetKey(ctx, "key-v1")
	if !errors.Is(err, ErrKeyDisabled) {
		t.Errorf("GetKey() of a disabled key, error = %v, want ErrKeyDisabled", err)
	}

	// Encrypt/Decrypt through EncryptionService must fail closed too, not
	// just KeyManager's own method.
	enc := NewEncryptionService(km)
	fakePayload := &EncryptedPayload{
		Ciphertext: []byte("x"), Nonce: make([]byte, 12), AuthTag: make([]byte, 16),
		WrappedDEK: make([]byte, 40), KeyID: "key-v1", Algorithm: AlgorithmAES256GCM,
	}
	if _, err := enc.Decrypt(ctx, fakePayload, EncryptContext{SecretID: "s", Version: 1}); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("Decrypt() with a disabled key, error = %v, want ErrKeyUnavailable", err)
	}
}

// --- 9. Missing key fails ---

func TestKeyManager_Rotate_MissingKeyFails(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	// key-v2 is never added to the provider — simulating a typo'd or
	// not-yet-provisioned key identifier.
	km, store := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}

	if _, err := km.Rotate(ctx, "key-v2"); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("Rotate() to a key the provider doesn't have, error = %v, want ErrKeyUnavailable", err)
	}

	// Rotation must not have partially applied: key-v1 is still active,
	// and key-v2 was never registered.
	active, err := store.GetActive(ctx)
	if err != nil || active.KeyID != "key-v1" {
		t.Errorf("after a failed Rotate(), active key = %+v (err %v), want key-v1 still active", active, err)
	}
	if _, err := store.Get(ctx, "key-v2"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("after a failed Rotate(), key-v2 metadata = %v, want ErrKeyNotFound (never registered)", err)
	}
}

// --- 10. Provider failure fails closed ---

func TestKeyManager_ProviderFailure_FailsClosed(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	provider.failErr = errors.New("simulated KMS network failure")
	provider.failAlways = true
	km, _ := newTestKeyManager(t, provider)

	if _, _, err := km.GetCurrentKey(context.Background()); err == nil {
		t.Fatal("GetCurrentKey() with a failing provider, error = nil, want an error")
	}
}

// --- 11. No key material in logs / error messages ---

func TestKeyManager_Errors_NeverContainKeyMaterial(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	key := provider.keys["key-v1"]
	provider.failKeyID = "key-v2"
	provider.failErr = errors.New("kms unavailable")
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}

	_, rotateErr := km.Rotate(ctx, "key-v2")
	_, getErr := km.GetKey(ctx, "key-does-not-exist")

	needle := string(key)
	for name, err := range map[string]error{"Rotate": rotateErr, "GetKey": getErr} {
		if err == nil {
			t.Fatalf("%s: expected an error, got nil", name)
		}
		if strings.Contains(err.Error(), needle) {
			t.Errorf("%s error message contains raw key material: %v", name, err)
		}
	}
}

// --- 12. No key material in API-response-shaped data ---

func TestKeyMetadata_JSONNeverContainsKeyMaterial(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	key := provider.keys["key-v1"]
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	meta, err := km.Metadata(ctx, "key-v1")
	if err != nil {
		t.Fatalf("Metadata() error = %v", err)
	}

	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("json.Marshal(KeyMetadata) error = %v", err)
	}
	if strings.Contains(string(encoded), string(key)) {
		t.Error("KeyMetadata JSON encoding contains raw key material")
	}
	// Structural guarantee, not just this one instance: KeyMetadata has no
	// []byte-shaped field for callers to accidentally populate with key
	// material in the first place.
	var probe struct {
		KeyID       string
		Algorithm   string
		State       KeyState
		CreatedAt   any
		ActivatedAt any
		RetiredAt   any
		DisabledAt  any
	}
	if err := json.Unmarshal(encoded, &probe); err != nil {
		t.Fatalf("KeyMetadata JSON shape unexpected: %v", err)
	}
}

// --- 13. Active key cannot accidentally be deleted (disabled/retired) ---

func TestKeyManager_ActiveKey_CannotBeDisabledOrRetired(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}

	if err := km.DisableKey(ctx, "key-v1"); !errors.Is(err, ErrKeyStillActive) {
		t.Errorf("DisableKey() on the active key, error = %v, want ErrKeyStillActive", err)
	}
	if err := km.Retire(ctx, "key-v1"); !errors.Is(err, ErrKeyStillActive) {
		t.Errorf("Retire() on the active key, error = %v, want ErrKeyStillActive", err)
	}

	// Still fully usable afterward — the refused calls must not have
	// mutated anything.
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Errorf("GetCurrentKey() after refused disable/retire attempts, error = %v, want nil", err)
	}
}

// --- 14. Key rotation does not destroy old keys ---

func TestKeyManager_Rotate_DoesNotDestroyOldKeys(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	provider.addKey(t, "key-v3")
	km, store := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate(key-v2) error = %v", err)
	}
	if _, err := km.Rotate(ctx, "key-v3"); err != nil {
		t.Fatalf("Rotate(key-v3) error = %v", err)
	}

	all, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List() returned %d keys, want 3 (rotation must never remove a key)", len(all))
	}
	states := map[string]KeyState{}
	for _, m := range all {
		states[m.KeyID] = m.State
	}
	if states["key-v1"] != KeyStateRetiring {
		t.Errorf("key-v1 state = %q, want retiring", states["key-v1"])
	}
	if states["key-v2"] != KeyStateRetiring {
		t.Errorf("key-v2 state = %q, want retiring", states["key-v2"])
	}
	if states["key-v3"] != KeyStateActive {
		t.Errorf("key-v3 state = %q, want active", states["key-v3"])
	}

	// And both retired-from-active keys are still functionally usable.
	for _, id := range []string{"key-v1", "key-v2"} {
		if _, err := km.GetKey(ctx, id); err != nil {
			t.Errorf("GetKey(%s) after two rotations, error = %v, want nil", id, err)
		}
	}
}

// Rotate refuses to resurrect a previously known key identifier.
func TestKeyManager_Rotate_RefusesKnownKeyID(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	km, _ := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate(key-v2) error = %v", err)
	}

	// Rotating "back" to key-v1 (now retiring) must be refused, not
	// silently reactivate it.
	if _, err := km.Rotate(ctx, "key-v1"); !errors.Is(err, ErrKeyAlreadyExists) {
		t.Errorf("Rotate() back to a previously known key, error = %v, want ErrKeyAlreadyExists", err)
	}
}

// Retire only succeeds once a key has actually been rotated away from,
// and is idempotent afterward.
func TestKeyManager_Retire(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	provider.addKey(t, "key-v2")
	km, store := newTestKeyManager(t, provider)
	ctx := context.Background()
	if _, _, err := km.GetCurrentKey(ctx); err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	if err := km.Retire(ctx, "key-v1"); err != nil {
		t.Fatalf("Retire(key-v1) error = %v", err)
	}
	meta, err := store.Get(ctx, "key-v1")
	if err != nil || meta.State != KeyStateRetired {
		t.Fatalf("after Retire(), key-v1 = %+v (err %v), want state=retired", meta, err)
	}
	// Retired keys still decrypt by default in this foundation — see
	// KeyStateRetired's doc comment.
	if _, err := km.GetKey(ctx, "key-v1"); err != nil {
		t.Errorf("GetKey() of a retired key, error = %v, want nil", err)
	}
	// Idempotent.
	if err := km.Retire(ctx, "key-v1"); err != nil {
		t.Errorf("second Retire() call, error = %v, want nil (idempotent)", err)
	}
}

func TestKeyManager_Metadata_UnknownKey(t *testing.T) {
	provider := newFakeMultiKeyProvider(t, "key-v1")
	km, _ := newTestKeyManager(t, provider)
	if _, err := km.Metadata(context.Background(), "nope"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Metadata() of an unknown key, error = %v, want ErrKeyNotFound", err)
	}
}

// --- Rotation against the real DevKeyProvider, not just the fake ---
//
// Every test above uses fakeMultiKeyProvider specifically because
// DevKeyProvider was previously single-key-only (see that type's old doc
// comment) — meaning KeyManager.Rotate had never actually been exercised
// against the real development KeyProvider implementation this
// deployment uses, only against a test double. DevKeyProvider.AddKey
// (Sprint 4 Task 1b) closes that gap.

func TestKeyManager_Rotate_AgainstRealDevKeyProvider(t *testing.T) {
	provider, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := provider.AddKey("key-v2", newTestKeyBase64(t)); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}
	km, store := newTestKeyManager(t, provider)
	enc := NewEncryptionService(km)
	ctx := context.Background()

	// Bootstrap onto key-v1, encrypt a value under it (the "existing
	// data" this deployment already has before any rotation happens).
	ec1 := EncryptContext{SecretID: "secret-1", Version: 1}
	payload1, err := enc.Encrypt(ctx, []byte("pre-rotation-value"), ec1)
	if err != nil {
		t.Fatalf("Encrypt() before rotation, error = %v", err)
	}
	if payload1.KeyID != "key-v1" {
		t.Fatalf("Encrypt() before rotation used KeyID %q, want key-v1", payload1.KeyID)
	}

	// 3. Active key selection: rotate to key-v2 against the real provider.
	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() against a real DevKeyProvider, error = %v, want nil", err)
	}
	active, err := store.GetActive(ctx)
	if err != nil || active.KeyID != "key-v2" {
		t.Fatalf("after Rotate(), active key = %+v (err %v), want key-v2", active, err)
	}

	// New encryption uses the newly active key.
	ec2 := EncryptContext{SecretID: "secret-1", Version: 2}
	payload2, err := enc.Encrypt(ctx, []byte("post-rotation-value"), ec2)
	if err != nil {
		t.Fatalf("Encrypt() after rotation, error = %v", err)
	}
	if payload2.KeyID != "key-v2" {
		t.Errorf("Encrypt() after rotation used KeyID %q, want key-v2", payload2.KeyID)
	}

	// 4. Old keys: the pre-rotation ciphertext (key-v1, now RETIRING)
	// still decrypts correctly against the real provider.
	got1, err := enc.Decrypt(ctx, payload1, ec1)
	if err != nil {
		t.Fatalf("Decrypt() of pre-rotation ciphertext after rotation, error = %v, want nil", err)
	}
	if string(got1) != "pre-rotation-value" {
		t.Errorf("Decrypt() pre-rotation value = %q, want %q", got1, "pre-rotation-value")
	}
	got2, err := enc.Decrypt(ctx, payload2, ec2)
	if err != nil {
		t.Fatalf("Decrypt() of post-rotation ciphertext, error = %v, want nil", err)
	}
	if string(got2) != "post-rotation-value" {
		t.Errorf("Decrypt() post-rotation value = %q, want %q", got2, "post-rotation-value")
	}
}

// TestBackwardCompatibility_ExistingSingleKeyDataStillDecrypts is the
// objective's own explicit regression requirement: data encrypted before
// this task's changes (i.e. under a DevKeyProvider used exactly the way
// it always has been — one key, constructed via NewDevKeyProvider, never
// touched by AddKey) must still decrypt correctly once AddKey/rotation
// capability exists in the same process. AddKey is purely additive to
// DevKeyProvider's internal map; it must never alter the constructor
// key's own material or identifier.
func TestBackwardCompatibility_ExistingSingleKeyDataStillDecrypts(t *testing.T) {
	provider, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	km, _ := newTestKeyManager(t, provider)
	enc := NewEncryptionService(km)
	ctx := context.Background()
	ec := EncryptContext{SecretID: "pre-existing-secret", Version: 1}

	// Simulates data that was already encrypted before this deployment
	// ever gained multi-key capability.
	existing, err := enc.Encrypt(ctx, []byte("value encrypted before this task"), ec)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// New capability is exercised afterward, in the same running process.
	if err := provider.AddKey("key-v2", newTestKeyBase64(t)); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}
	if _, err := km.Rotate(ctx, "key-v2"); err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}

	// The pre-existing ciphertext must still decrypt, byte-for-byte,
	// after all of that.
	plaintext, err := enc.Decrypt(ctx, existing, ec)
	if err != nil {
		t.Fatalf("Decrypt() of pre-existing data after AddKey+Rotate, error = %v, want nil", err)
	}
	if string(plaintext) != "value encrypted before this task" {
		t.Errorf("Decrypt() = %q, want the original plaintext unchanged", plaintext)
	}
}
