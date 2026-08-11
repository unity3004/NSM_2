package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// fakeKeyProvider is a minimal KeyProvider for test scenarios
// NewDevKeyProvider itself can't produce — an unreachable key store, or a
// key that returns successfully but is the wrong bytes for a given ID
// (simulating an operator misconfiguration, not a malformed config
// value).
type fakeKeyProvider struct {
	currentKey   []byte
	currentKeyID string
	keys         map[string][]byte
	err          error
}

// GetCurrentKey and GetKey both return a fresh copy, never a reference to
// f's own stored slices — the same independent-copy contract
// DevKeyProvider honors (see its copyKey). EncryptionService zeroes
// whatever key material it receives once it's done with it (see
// zero(kek) in Encrypt/Decrypt); a fake that skipped this copy would have
// its own stored key silently erased by the first Encrypt/Decrypt call
// that used it, corrupting every later lookup in the same test — exactly
// the bug this fake existed to help catch elsewhere, so it must not
// commit it itself.
func (f *fakeKeyProvider) GetCurrentKey(ctx context.Context) ([]byte, string, error) {
	if f.err != nil {
		return nil, "", f.err
	}
	return append([]byte{}, f.currentKey...), f.currentKeyID, nil
}

func (f *fakeKeyProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	k, ok := f.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return append([]byte{}, k...), nil
}

// mustRandomKey panics on a crypto/rand failure rather than taking a
// *testing.T, so both ordinary tests and benchmarks (which cannot safely
// construct a *testing.T of their own — a zero-value one isn't wired to
// the test framework) can share one key-generation helper.
func mustRandomKey() []byte {
	key := make([]byte, dekLength)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func newTestKey(t *testing.T) []byte {
	t.Helper()
	return mustRandomKey()
}

func newFakeProvider() *fakeKeyProvider {
	key := mustRandomKey()
	return &fakeKeyProvider{
		currentKey:   key,
		currentKeyID: "test-key-1",
		keys:         map[string][]byte{"test-key-1": key},
	}
}

func newTestService(t *testing.T) (*EncryptionService, *fakeKeyProvider) {
	t.Helper()
	provider := newFakeProvider()
	return NewEncryptionService(provider), provider
}

var testEC = EncryptContext{SecretID: "11111111-1111-4111-8111-111111111111", Version: 1}

// --- 1. Encrypt plaintext successfully ---

func TestEncrypt_Succeeds(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("super-secret-value"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v, want nil", err)
	}
	if payload == nil {
		t.Fatal("Encrypt() returned a nil payload with a nil error")
	}
	if len(payload.Ciphertext) == 0 {
		t.Error("Encrypt() produced empty Ciphertext for non-empty plaintext")
	}
	if len(payload.Nonce) == 0 {
		t.Error("Encrypt() produced an empty Nonce")
	}
	if len(payload.AuthTag) == 0 {
		t.Error("Encrypt() produced an empty AuthTag")
	}
	if len(payload.WrappedDEK) == 0 {
		t.Error("Encrypt() produced an empty WrappedDEK")
	}
	if payload.KeyID != "test-key-1" {
		t.Errorf("Encrypt() KeyID = %q, want %q", payload.KeyID, "test-key-1")
	}
	if payload.Algorithm != AlgorithmAES256GCM {
		t.Errorf("Encrypt() Algorithm = %q, want %q", payload.Algorithm, AlgorithmAES256GCM)
	}
}

// --- 2 & 3. Decrypt successfully; plaintext after decrypt equals original ---

func TestEncryptDecrypt_RoundTrip_PlaintextUnchanged(t *testing.T) {
	svc, _ := newTestService(t)
	original := []byte("correct-horse-battery-staple-42")

	payload, err := svc.Encrypt(context.Background(), original, testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	got, err := svc.Decrypt(context.Background(), payload, testEC)
	if err != nil {
		t.Fatalf("Decrypt() error = %v, want nil", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("Decrypt() = %q, want %q", got, original)
	}
}

// --- 4. Encrypting identical plaintext twice produces different ciphertext/nonces ---

func TestEncrypt_SamePlaintextTwice_ProducesDifferentCiphertextAndNonce(t *testing.T) {
	svc, _ := newTestService(t)
	plaintext := []byte("identical-plaintext")

	first, err := svc.Encrypt(context.Background(), plaintext, testEC)
	if err != nil {
		t.Fatalf("Encrypt() #1 error = %v", err)
	}
	second, err := svc.Encrypt(context.Background(), plaintext, testEC)
	if err != nil {
		t.Fatalf("Encrypt() #2 error = %v", err)
	}

	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Error("two Encrypt() calls produced the same nonce — nonces must be freshly random every time")
	}
	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Error("two Encrypt() calls on identical plaintext produced identical ciphertext")
	}
	if bytes.Equal(first.WrappedDEK, second.WrappedDEK) {
		t.Error("two Encrypt() calls produced the same wrapped DEK — each operation must use a fresh, single-use DEK")
	}

	// Both must still independently decrypt back to the same plaintext.
	for i, p := range []*EncryptedPayload{first, second} {
		got, err := svc.Decrypt(context.Background(), p, testEC)
		if err != nil {
			t.Fatalf("Decrypt() payload #%d error = %v", i+1, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("Decrypt() payload #%d = %q, want %q", i+1, got, plaintext)
		}
	}
}

// --- 5. Tampered ciphertext fails authentication ---

func TestDecrypt_TamperedCiphertext_FailsAuthentication(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("tamper-me"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	tampered := *payload
	tampered.Ciphertext = append([]byte{}, payload.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xFF

	got, err := svc.Decrypt(context.Background(), &tampered, testEC)
	if !errors.Is(err, ErrCiphertextInvalid) {
		t.Errorf("Decrypt() with tampered ciphertext, error = %v, want ErrCiphertextInvalid", err)
	}
	if got != nil {
		t.Error("Decrypt() with tampered ciphertext returned non-nil plaintext — must never return partial/corrupted plaintext")
	}
}

// Tampering with the authentication tag itself must be caught the same way.
func TestDecrypt_TamperedAuthTag_FailsAuthentication(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("tamper-my-tag"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	tampered := *payload
	tampered.AuthTag = append([]byte{}, payload.AuthTag...)
	tampered.AuthTag[0] ^= 0xFF

	if _, err := svc.Decrypt(context.Background(), &tampered, testEC); !errors.Is(err, ErrCiphertextInvalid) {
		t.Errorf("Decrypt() with a tampered auth tag, error = %v, want ErrCiphertextInvalid", err)
	}
}

// --- 6. Tampered nonce fails ---

func TestDecrypt_TamperedNonce_Fails(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("nonce-tamper"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	tampered := *payload
	tampered.Nonce = append([]byte{}, payload.Nonce...)
	tampered.Nonce[0] ^= 0xFF

	if _, err := svc.Decrypt(context.Background(), &tampered, testEC); !errors.Is(err, ErrCiphertextInvalid) {
		t.Errorf("Decrypt() with a tampered nonce, error = %v, want ErrCiphertextInvalid", err)
	}
}

// --- 7. Wrong key fails ---

func TestDecrypt_WrongKey_Fails(t *testing.T) {
	svc, provider := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("wrong-key-test"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Same key ID, but the provider now hands back different key bytes
	// under it — simulating an operator misconfiguration (e.g. the wrong
	// key material loaded under the right label), not a lookup failure.
	provider.keys["test-key-1"] = newTestKey(t)

	got, err := svc.Decrypt(context.Background(), payload, testEC)
	if !errors.Is(err, ErrCiphertextInvalid) {
		t.Errorf("Decrypt() with the wrong key material under the same key ID, error = %v, want ErrCiphertextInvalid", err)
	}
	if got != nil {
		t.Error("Decrypt() with the wrong key returned non-nil plaintext")
	}
}

// --- 8. Missing key fails safely ---

func TestEncrypt_MissingKey_FailsSafely(t *testing.T) {
	svc := NewEncryptionService(&fakeKeyProvider{err: ErrKeyProviderMisconfigured})
	_, err := svc.Encrypt(context.Background(), []byte("plaintext"), testEC)
	if !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("Encrypt() with no key available, error = %v, want ErrKeyUnavailable", err)
	}
}

func TestDecrypt_MissingKey_FailsSafely(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("plaintext"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// A provider that no longer knows about payload.KeyID at all — e.g.
	// the key was deleted, or this is a different environment's provider.
	svc2 := NewEncryptionService(&fakeKeyProvider{keys: map[string][]byte{}})
	_, err = svc2.Decrypt(context.Background(), payload, testEC)
	if !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("Decrypt() with an unknown key ID, error = %v, want ErrKeyUnavailable", err)
	}
}

// --- 9. Invalid key length fails safely ---

func TestEncrypt_InvalidKeyLength_FailsSafely(t *testing.T) {
	svc := NewEncryptionService(&fakeKeyProvider{currentKey: []byte("too-short"), currentKeyID: "bad-key"})
	_, err := svc.Encrypt(context.Background(), []byte("plaintext"), testEC)
	if !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("Encrypt() with a wrong-length key, error = %v, want ErrKeyUnavailable", err)
	}
}

func TestDecrypt_InvalidKeyLength_FailsSafely(t *testing.T) {
	svc := NewEncryptionService(&fakeKeyProvider{
		keys: map[string][]byte{"bad-key": []byte("too-short")},
	})
	payload := &EncryptedPayload{
		Ciphertext: []byte("x"), Nonce: make([]byte, 12), AuthTag: make([]byte, 16),
		WrappedDEK: make([]byte, 28), KeyID: "bad-key", Algorithm: AlgorithmAES256GCM,
	}
	if _, err := svc.Decrypt(context.Background(), payload, testEC); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("Decrypt() with a wrong-length stored key, error = %v, want ErrKeyUnavailable", err)
	}
}

// --- 10. Unsupported algorithm fails safely ---

func TestDecrypt_UnsupportedAlgorithm_FailsSafely(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("plaintext"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	payload.Algorithm = "ROT13" // never a real algorithm this package supports

	if _, err := svc.Decrypt(context.Background(), payload, testEC); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("Decrypt() with an unsupported algorithm, error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// --- 11. Empty plaintext is handled according to the design ---

// This package's design choice: an empty secret value is a valid input —
// AES-GCM has no minimum plaintext length, and Encrypt/Decrypt round-trip
// it like any other value, still producing a real nonce and a real
// authentication tag (an attacker still cannot forge an "empty" ciphertext
// without the key).
func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte{}, testEC)
	if err != nil {
		t.Fatalf("Encrypt() with empty plaintext, error = %v, want nil", err)
	}
	if len(payload.AuthTag) == 0 {
		t.Error("Encrypt() with empty plaintext produced an empty AuthTag — GCM must still authenticate an empty message")
	}

	got, err := svc.Decrypt(context.Background(), payload, testEC)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Decrypt() of an empty-plaintext payload = %q, want empty", got)
	}
}

// --- 12. Large payload behavior is reasonable ---

func TestEncryptDecrypt_LargePayload(t *testing.T) {
	svc, _ := newTestService(t)
	large := make([]byte, 1<<20) // 1 MiB
	if _, err := rand.Read(large); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	payload, err := svc.Encrypt(context.Background(), large, testEC)
	if err != nil {
		t.Fatalf("Encrypt() of a 1 MiB payload, error = %v", err)
	}
	got, err := svc.Decrypt(context.Background(), payload, testEC)
	if err != nil {
		t.Fatalf("Decrypt() of a 1 MiB payload, error = %v", err)
	}
	if !bytes.Equal(got, large) {
		t.Error("Decrypt() of a 1 MiB payload did not round-trip correctly")
	}
}

// --- 13. AAD modification causes authentication failure ---

func TestDecrypt_AADMismatch_FailsAuthentication(t *testing.T) {
	svc, _ := newTestService(t)
	payload, err := svc.Encrypt(context.Background(), []byte("bound-to-context"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	t.Run("different secret ID", func(t *testing.T) {
		wrongEC := EncryptContext{SecretID: "22222222-2222-4222-8222-222222222222", Version: testEC.Version}
		if _, err := svc.Decrypt(context.Background(), payload, wrongEC); !errors.Is(err, ErrCiphertextInvalid) {
			t.Errorf("Decrypt() with a different SecretID, error = %v, want ErrCiphertextInvalid", err)
		}
	})

	t.Run("different version", func(t *testing.T) {
		wrongEC := EncryptContext{SecretID: testEC.SecretID, Version: testEC.Version + 1}
		if _, err := svc.Decrypt(context.Background(), payload, wrongEC); !errors.Is(err, ErrCiphertextInvalid) {
			t.Errorf("Decrypt() with a different Version, error = %v, want ErrCiphertextInvalid", err)
		}
	})

	// Simulates an attacker moving an entire row's encrypted columns onto
	// a different secret_versions row without touching any of them — the
	// exact scenario EncryptContext's AAD binding exists to defeat (see
	// its doc comment).
	t.Run("full row moved to a different secret and version", func(t *testing.T) {
		movedEC := EncryptContext{SecretID: "33333333-3333-4333-8333-333333333333", Version: 7}
		if _, err := svc.Decrypt(context.Background(), payload, movedEC); !errors.Is(err, ErrCiphertextInvalid) {
			t.Errorf("Decrypt() of a payload moved to a different secret_id/version, error = %v, want ErrCiphertextInvalid", err)
		}
	})
}

// --- 14. Key identifiers are handled correctly ---

func TestEncryptDecrypt_KeyIdentifiers(t *testing.T) {
	keyA := newTestKey(t)
	keyB := newTestKey(t)
	provider := &fakeKeyProvider{
		currentKey:   keyA,
		currentKeyID: "key-a",
		keys:         map[string][]byte{"key-a": keyA, "key-b": keyB},
	}
	svc := NewEncryptionService(provider)

	payload, err := svc.Encrypt(context.Background(), []byte("under-key-a"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if payload.KeyID != "key-a" {
		t.Fatalf("Encrypt() KeyID = %q, want %q", payload.KeyID, "key-a")
	}

	// Switch which key is "current" — new encryptions move to key-b, but
	// the payload already encrypted under key-a must still name key-a and
	// still decrypt correctly, because GetKey (not GetCurrentKey) is what
	// Decrypt uses.
	provider.currentKey, provider.currentKeyID = keyB, "key-b"

	next, err := svc.Encrypt(context.Background(), []byte("under-key-b"), testEC)
	if err != nil {
		t.Fatalf("Encrypt() after switching current key, error = %v", err)
	}
	if next.KeyID != "key-b" {
		t.Errorf("Encrypt() after switching current key, KeyID = %q, want %q", next.KeyID, "key-b")
	}

	got, err := svc.Decrypt(context.Background(), payload, testEC)
	if err != nil {
		t.Fatalf("Decrypt() of a payload encrypted under the no-longer-current key, error = %v", err)
	}
	if string(got) != "under-key-a" {
		t.Errorf("Decrypt() = %q, want %q", got, "under-key-a")
	}
}

// --- 15. No secret/key material appears in logs ---
//
// internal/secrets has no logging dependency at all (see the package doc
// comment), so the practical form of this requirement is: nothing this
// package returns — in particular, no error's message — ever contains the
// plaintext or key bytes involved in an operation. That's what a caller's
// `log.Error(err)` would actually emit if this package were ever wired
// into one.
func TestErrors_NeverContainSensitiveMaterial(t *testing.T) {
	const plaintextMarker = "THIS_IS_TEST_SECRET_VALUE"
	svc, provider := newTestService(t)
	ctx := context.Background()

	payload, err := svc.Encrypt(ctx, []byte(plaintextMarker), testEC)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	keyMarker := string(provider.currentKey)

	var errs []error
	_, errFromMissingKey := NewEncryptionService(&fakeKeyProvider{err: ErrKeyProviderMisconfigured}).Encrypt(ctx, []byte(plaintextMarker), testEC)
	errs = append(errs, errFromMissingKey)

	tampered := *payload
	tampered.Ciphertext = append([]byte{}, payload.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xFF
	_, errFromTamper := svc.Decrypt(ctx, &tampered, testEC)
	errs = append(errs, errFromTamper)

	badAlg := *payload
	badAlg.Algorithm = "unsupported"
	_, errFromAlg := svc.Decrypt(ctx, &badAlg, testEC)
	errs = append(errs, errFromAlg)

	for i, e := range errs {
		if e == nil {
			continue
		}
		msg := e.Error()
		if strings.Contains(msg, plaintextMarker) {
			t.Errorf("error #%d message %q contains the plaintext value", i, msg)
		}
		if strings.Contains(msg, keyMarker) {
			t.Errorf("error #%d message %q contains raw key material", i, msg)
		}
	}

	// The payload's own String() must also stay safe — see
	// EncryptedPayload.String's doc comment.
	summary := payload.String()
	if strings.Contains(summary, plaintextMarker) {
		t.Errorf("EncryptedPayload.String() = %q contains the plaintext value", summary)
	}
	if strings.Contains(summary, string(payload.Ciphertext)) && len(payload.Ciphertext) > 0 {
		t.Error("EncryptedPayload.String() contains raw ciphertext bytes")
	}
}

// --- Benchmarks ---

func benchmarkPlaintext(size int) []byte {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return b
}

func BenchmarkEncrypt_1KiB(b *testing.B) {
	svc := NewEncryptionService(newFakeProvider())
	plaintext := benchmarkPlaintext(1024)
	b.ResetTimer()
	for b.Loop() {
		if _, err := svc.Encrypt(context.Background(), plaintext, testEC); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt_64KiB(b *testing.B) {
	svc := NewEncryptionService(newFakeProvider())
	plaintext := benchmarkPlaintext(64 * 1024)
	b.ResetTimer()
	for b.Loop() {
		if _, err := svc.Encrypt(context.Background(), plaintext, testEC); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt_1KiB(b *testing.B) {
	svc := NewEncryptionService(newFakeProvider())
	payload, err := svc.Encrypt(context.Background(), benchmarkPlaintext(1024), testEC)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := svc.Decrypt(context.Background(), payload, testEC); err != nil {
			b.Fatal(err)
		}
	}
}
