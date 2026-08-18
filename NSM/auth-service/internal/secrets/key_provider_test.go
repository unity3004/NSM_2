package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// newTestKeyBase64 generates a fresh, random 256-bit key for test use —
// never a literal string, never reused across the security review's
// "generated test keys, not real secrets" requirement.
func newTestKeyBase64(t *testing.T) string {
	t.Helper()
	key := make([]byte, devKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// --- Construction ---

func TestNewDevKeyProvider_Succeeds(t *testing.T) {
	p, err := NewDevKeyProvider("test-key-1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v, want nil", err)
	}
	if p == nil {
		t.Fatal("NewDevKeyProvider() returned a nil provider with a nil error")
	}
}

func TestNewDevKeyProvider_MissingKeyID(t *testing.T) {
	_, err := NewDevKeyProvider("", newTestKeyBase64(t))
	if err == nil {
		t.Fatal("NewDevKeyProvider() with an empty key ID, error = nil, want an error")
	}
}

// Missing key fails safely (test requirement #8).
func TestNewDevKeyProvider_MissingKeyMaterial(t *testing.T) {
	_, err := NewDevKeyProvider("test-key-1", "")
	if !errors.Is(err, ErrKeyProviderMisconfigured) {
		t.Errorf("NewDevKeyProvider() with no key material, error = %v, want ErrKeyProviderMisconfigured", err)
	}
}

func TestNewDevKeyProvider_InvalidBase64(t *testing.T) {
	_, err := NewDevKeyProvider("test-key-1", "not-valid-base64!!!")
	if !errors.Is(err, ErrKeyProviderMisconfigured) {
		t.Errorf("NewDevKeyProvider() with invalid base64, error = %v, want ErrKeyProviderMisconfigured", err)
	}
}

// Invalid key length fails safely (test requirement #9).
func TestNewDevKeyProvider_WrongKeyLength(t *testing.T) {
	tests := []struct {
		name      string
		byteCount int
	}{
		{"too short (16 bytes / AES-128 length)", 16},
		{"too long (64 bytes)", 64},
		{"empty", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.byteCount)
			if _, err := rand.Read(key); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			_, err := NewDevKeyProvider("test-key-1", base64.StdEncoding.EncodeToString(key))
			if !errors.Is(err, ErrKeyProviderMisconfigured) {
				t.Errorf("NewDevKeyProvider() with a %d-byte key, error = %v, want ErrKeyProviderMisconfigured", tt.byteCount, err)
			}
		})
	}
}

// --- Key retrieval ---

func TestDevKeyProvider_GetCurrentKey(t *testing.T) {
	keyB64 := newTestKeyBase64(t)
	p, err := NewDevKeyProvider("test-key-1", keyB64)
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}

	key, keyID, err := p.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if keyID != "test-key-1" {
		t.Errorf("GetCurrentKey() keyID = %q, want %q", keyID, "test-key-1")
	}
	wantKey, _ := base64.StdEncoding.DecodeString(keyB64)
	if string(key) != string(wantKey) {
		t.Error("GetCurrentKey() returned different key bytes than were configured")
	}
}

// Key identifiers are handled correctly (test requirement #14).
func TestDevKeyProvider_GetKey(t *testing.T) {
	p, err := NewDevKeyProvider("test-key-1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}

	if _, err := p.GetKey(context.Background(), "test-key-1"); err != nil {
		t.Errorf("GetKey() with the configured key ID, error = %v, want nil", err)
	}

	_, err = p.GetKey(context.Background(), "some-other-key-id")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("GetKey() with an unknown key ID, error = %v, want ErrKeyNotFound", err)
	}
}

// Each call must return an independent copy: mutating what one call
// returned must never corrupt the provider's own retained key material or
// leak into a later, unrelated call's result.
func TestDevKeyProvider_ReturnsIndependentCopies(t *testing.T) {
	p, err := NewDevKeyProvider("test-key-1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}

	first, _, err := p.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	for i := range first {
		first[i] = 0xFF
	}

	second, _, err := p.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	allZero := true
	for _, b := range second {
		if b != 0xFF {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("mutating one GetCurrentKey() result corrupted a later call's result — the provider is not returning independent copies")
	}
}

// --- Multiple keys (Sprint 4 Task 1b: AddKey) ---

func TestDevKeyProvider_AddKey_ThenGetKey_ResolvesBothKeys(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	v2B64 := newTestKeyBase64(t)
	if err := p.AddKey("key-v2", v2B64); err != nil {
		t.Fatalf("AddKey() error = %v, want nil", err)
	}

	if _, err := p.GetKey(context.Background(), "key-v1"); err != nil {
		t.Errorf("GetKey(key-v1) after AddKey(key-v2), error = %v, want nil (the original key must remain resolvable)", err)
	}
	got, err := p.GetKey(context.Background(), "key-v2")
	if err != nil {
		t.Fatalf("GetKey(key-v2) error = %v, want nil", err)
	}
	want, _ := base64.StdEncoding.DecodeString(v2B64)
	if string(got) != string(want) {
		t.Error("GetKey(key-v2) returned different key bytes than AddKey was given")
	}
}

// GetCurrentKey's contract is "the key this provider was constructed
// with" — see its own doc comment for why AddKey deliberately does not
// change that (KeyManager never re-asks a provider what's current after
// bootstrap).
func TestDevKeyProvider_AddKey_DoesNotChangeGetCurrentKey(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("key-v2", newTestKeyBase64(t)); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}

	_, keyID, err := p.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if keyID != "key-v1" {
		t.Errorf("GetCurrentKey() keyID = %q after AddKey(key-v2), want %q (unchanged)", keyID, "key-v1")
	}
}

func TestDevKeyProvider_AddKey_DuplicateKeyIDFails(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("key-v1", newTestKeyBase64(t)); err == nil {
		t.Fatal("AddKey() with an already-registered key ID, error = nil, want an error")
	}
	// The original key's material must be unaffected by the refused
	// overwrite attempt.
	if _, err := p.GetKey(context.Background(), "key-v1"); err != nil {
		t.Errorf("GetKey(key-v1) after a refused duplicate AddKey(), error = %v, want nil", err)
	}
}

func TestDevKeyProvider_AddKey_MissingKeyIDFails(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("", newTestKeyBase64(t)); err == nil {
		t.Fatal("AddKey() with an empty key ID, error = nil, want an error")
	}
}

func TestDevKeyProvider_AddKey_InvalidBase64Fails(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("key-v2", "not-valid-base64!!!"); !errors.Is(err, ErrKeyProviderMisconfigured) {
		t.Errorf("AddKey() with invalid base64, error = %v, want ErrKeyProviderMisconfigured", err)
	}
	if _, err := p.GetKey(context.Background(), "key-v2"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("GetKey(key-v2) after a rejected AddKey(), error = %v, want ErrKeyNotFound (must not be partially registered)", err)
	}
}

func TestDevKeyProvider_AddKey_WrongLengthFails(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	short := make([]byte, 16)
	if err := p.AddKey("key-v2", base64.StdEncoding.EncodeToString(short)); !errors.Is(err, ErrKeyProviderMisconfigured) {
		t.Errorf("AddKey() with a 16-byte key, error = %v, want ErrKeyProviderMisconfigured", err)
	}
}

func TestDevKeyProvider_AddKey_MissingMaterialFails(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("key-v2", ""); !errors.Is(err, ErrKeyProviderMisconfigured) {
		t.Errorf("AddKey() with no key material, error = %v, want ErrKeyProviderMisconfigured", err)
	}
}

// Unknown key IDs remain refused after AddKey has been used at least
// once — AddKey must not accidentally widen GetKey into accepting
// anything.
func TestDevKeyProvider_GetKey_StillRefusesUnknownIDAfterAddKey(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("key-v2", newTestKeyBase64(t)); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}
	if _, err := p.GetKey(context.Background(), "key-v3-never-added"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("GetKey() with an unregistered key ID, error = %v, want ErrKeyNotFound", err)
	}
}

// Each registered key's GetKey result must be an independent copy, the
// same guarantee TestDevKeyProvider_ReturnsIndependentCopies already
// proves for the constructor's own key — mutating one key ID's returned
// bytes must never corrupt another key ID's stored material.
func TestDevKeyProvider_AddKey_ReturnsIndependentCopies(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("key-v2", newTestKeyBase64(t)); err != nil {
		t.Fatalf("AddKey() error = %v", err)
	}

	got, err := p.GetKey(context.Background(), "key-v2")
	if err != nil {
		t.Fatalf("GetKey(key-v2) error = %v", err)
	}
	for i := range got {
		got[i] = 0xAB
	}
	again, err := p.GetKey(context.Background(), "key-v2")
	if err != nil {
		t.Fatalf("GetKey(key-v2) second call, error = %v", err)
	}
	allMutated := true
	for _, b := range again {
		if b != 0xAB {
			allMutated = false
			break
		}
	}
	if allMutated {
		t.Fatal("mutating one GetKey() result corrupted the provider's own stored key material")
	}
}

// --- GenerateKey (KeyGenerator) ---

func TestDevKeyProvider_GenerateKey_ProducesUsableKey(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}

	keyID, err := p.GenerateKey(context.Background())
	if err != nil {
		t.Fatalf("GenerateKey() error = %v, want nil", err)
	}
	if keyID == "" || keyID == "key-v1" {
		t.Fatalf("GenerateKey() returned keyID %q, want a new, non-empty identifier", keyID)
	}
	key, err := p.GetKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("GetKey(%q) after GenerateKey(), error = %v, want nil", keyID, err)
	}
	if len(key) != devKeyLength {
		t.Errorf("GenerateKey()'s key material is %d bytes, want %d", len(key), devKeyLength)
	}
}

func TestDevKeyProvider_GenerateKey_SequentialIDs(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}

	first, err := p.GenerateKey(context.Background())
	if err != nil {
		t.Fatalf("first GenerateKey() error = %v", err)
	}
	if first != "key-v2" {
		t.Errorf("first GenerateKey() = %q, want %q", first, "key-v2")
	}
	second, err := p.GenerateKey(context.Background())
	if err != nil {
		t.Fatalf("second GenerateKey() error = %v", err)
	}
	if second != "key-v3" {
		t.Errorf("second GenerateKey() = %q, want %q", second, "key-v3")
	}
}

// GenerateKey must keep working correctly even when a key was registered
// out of sequence (or with a non-key-vN-shaped ID) via AddKey directly —
// it scans existing IDs rather than trusting a separate counter.
func TestDevKeyProvider_GenerateKey_ContinuesCorrectlyAfterManualAddKey(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if err := p.AddKey("key-v5", newTestKeyBase64(t)); err != nil {
		t.Fatalf("AddKey(key-v5) error = %v", err)
	}
	if err := p.AddKey("operator-provisioned-key", newTestKeyBase64(t)); err != nil {
		t.Fatalf("AddKey(operator-provisioned-key) error = %v", err)
	}

	next, err := p.GenerateKey(context.Background())
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if next != "key-v6" {
		t.Errorf("GenerateKey() after key-v5 was added manually = %q, want %q", next, "key-v6")
	}
}

func TestDevKeyProvider_GenerateKey_DoesNotChangeGetCurrentKey(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	if _, err := p.GenerateKey(context.Background()); err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	_, keyID, err := p.GetCurrentKey(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentKey() error = %v", err)
	}
	if keyID != "key-v1" {
		t.Errorf("GetCurrentKey() keyID = %q after GenerateKey(), want %q (unchanged)", keyID, "key-v1")
	}
}

func TestDevKeyProvider_GenerateKey_ProducesUniqueMaterialEachCall(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}

	id1, err := p.GenerateKey(context.Background())
	if err != nil {
		t.Fatalf("first GenerateKey() error = %v", err)
	}
	id2, err := p.GenerateKey(context.Background())
	if err != nil {
		t.Fatalf("second GenerateKey() error = %v", err)
	}
	key1, err := p.GetKey(context.Background(), id1)
	if err != nil {
		t.Fatalf("GetKey(%q) error = %v", id1, err)
	}
	key2, err := p.GetKey(context.Background(), id2)
	if err != nil {
		t.Fatalf("GetKey(%q) error = %v", id2, err)
	}
	if string(key1) == string(key2) {
		t.Fatal("two GenerateKey() calls produced identical key material")
	}
}

// Compile-time interface satisfaction is asserted in key_provider.go
// itself; this proves it holds at the call-site level too, the way
// service.KeyRotationService actually uses it (as a plain KeyGenerator
// value, no concrete-type knowledge).
func TestDevKeyProvider_SatisfiesKeyGenerator(t *testing.T) {
	p, err := NewDevKeyProvider("key-v1", newTestKeyBase64(t))
	if err != nil {
		t.Fatalf("NewDevKeyProvider() error = %v", err)
	}
	var gen KeyGenerator = p
	if _, err := gen.GenerateKey(context.Background()); err != nil {
		t.Errorf("DevKeyProvider used as a bare KeyGenerator, GenerateKey() error = %v, want nil", err)
	}
}
