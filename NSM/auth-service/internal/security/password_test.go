package security

import (
	"errors"
	"strings"
	"testing"
)

// fastParams keeps the test suite fast without changing what's being
// tested: Argon2id's correctness doesn't depend on the cost parameters,
// and DefaultParams' ~300ms/hash would make this file slow to run
// repeatedly during development.
var fastParams = Params{
	Memory:      8 * 1024, // 8 MiB — still well above the 8*parallelism floor
	Iterations:  1,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func newTestService(t *testing.T) *PasswordService {
	t.Helper()
	return NewPasswordService(fastParams)
}

// --- Successful hashing ---

func TestHash_Succeeds(t *testing.T) {
	svc := newTestService(t)

	encoded, err := svc.Hash("Tr0ub4dor&3xample!")
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}
	if encoded == "" {
		t.Fatal("Hash() returned an empty string")
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=") {
		t.Errorf("Hash() = %q, want it to start with %q", encoded, "$argon2id$v=")
	}
}

// --- Hash format validation ---

func TestHash_OutputFormat(t *testing.T) {
	svc := newTestService(t)

	encoded, err := svc.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("Hash() produced %d '$'-separated fields, want 6 (got %q)", len(parts), encoded)
	}
	if parts[0] != "" || parts[1] != "argon2id" {
		t.Errorf("Hash() fields[0:2] = %q, %q, want \"\", \"argon2id\"", parts[0], parts[1])
	}
	wantParamsField := "m=8192,t=1,p=2"
	if parts[3] != wantParamsField {
		t.Errorf("Hash() params field = %q, want %q", parts[3], wantParamsField)
	}

	// The encoded hash must itself pass this package's own parser —
	// round-tripping through decodeHash is what Verify relies on.
	if _, _, _, err := decodeHash(encoded); err != nil {
		t.Errorf("decodeHash(Hash(...)) error = %v, want nil — Hash must produce output its own Verify can parse", err)
	}
}

// --- Successful verification ---

func TestVerify_Succeeds(t *testing.T) {
	svc := newTestService(t)
	const password = "Tr0ub4dor&3xample!"

	encoded, err := svc.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	match, err := svc.Verify(password, encoded)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if !match {
		t.Error("Verify() = false, want true for the correct password")
	}
}

// --- Incorrect password ---

func TestVerify_IncorrectPassword(t *testing.T) {
	svc := newTestService(t)

	encoded, err := svc.Hash("the-real-password")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	match, err := svc.Verify("a-completely-different-password", encoded)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil (a wrong password is not an error)", err)
	}
	if match {
		t.Error("Verify() = true, want false for an incorrect password")
	}
}

// --- Different passwords producing different hashes ---

func TestHash_DifferentPasswordsProduceDifferentHashes(t *testing.T) {
	svc := newTestService(t)

	h1, err := svc.Hash("password-one")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	h2, err := svc.Hash("password-two")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if h1 == h2 {
		t.Error("Hash() of two different passwords produced identical output")
	}
}

// --- Same password producing different hashes because of random salts ---

func TestHash_SamePasswordProducesDifferentHashesEachTime(t *testing.T) {
	svc := newTestService(t)
	const password = "the-same-password"

	h1, err := svc.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	h2, err := svc.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if h1 == h2 {
		t.Fatal("Hash() of the same password twice produced identical output — salts are not being randomized")
	}

	// Both must still independently verify — different encodings of the
	// same password are not the same as one of them being wrong.
	for _, h := range []string{h1, h2} {
		match, err := svc.Verify(password, h)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !match {
			t.Errorf("Verify(%q, %q) = false, want true", password, h)
		}
	}

	salt1 := strings.Split(h1, "$")[4]
	salt2 := strings.Split(h2, "$")[4]
	if salt1 == salt2 {
		t.Error("two Hash() calls for the same password produced the same salt — crypto/rand may not be wired up correctly")
	}
}

// --- Invalid encoded hash ---

func TestVerify_InvalidEncodedHash(t *testing.T) {
	svc := newTestService(t)

	tests := map[string]string{
		"empty string":           "",
		"not argon2 at all":      "not-a-hash",
		"wrong variant":          "$argon2i$v=19$m=8192,t=1,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"unsupported version":    "$argon2id$v=1$m=8192,t=1,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"non-numeric params":     "$argon2id$v=19$m=abc,t=1,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"zero iterations":        "$argon2id$v=19$m=8192,t=0,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"zero parallelism":       "$argon2id$v=19$m=8192,t=1,p=0$c2FsdHNhbHQ$aGFzaGhhc2g",
		"memory below floor":     "$argon2id$v=19$m=1,t=1,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
		"salt is not base64":     "$argon2id$v=19$m=8192,t=1,p=2$not-valid-base64!!$aGFzaGhhc2g",
		"empty salt":             "$argon2id$v=19$m=8192,t=1,p=2$$aGFzaGhhc2g",
		"empty hash segment":     "$argon2id$v=19$m=8192,t=1,p=2$c2FsdHNhbHQ$",
		"too few fields":         "$argon2id$v=19$m=8192,t=1,p=2$c2FsdHNhbHQ",
		"missing leading dollar": "argon2id$v=19$m=8192,t=1,p=2$c2FsdHNhbHQ$aGFzaGhhc2g",
	}

	for name, hash := range tests {
		t.Run(name, func(t *testing.T) {
			match, err := svc.Verify("any-password", hash)
			if err == nil {
				t.Errorf("Verify() with %s = nil error, want a non-nil error", name)
			}
			if match {
				t.Errorf("Verify() with %s = true, want false", name)
			}
		})
	}
}

func TestVerify_EmptyEncodedHash(t *testing.T) {
	svc := newTestService(t)

	_, err := svc.Verify("any-password", "")
	if !errors.Is(err, ErrEmptyHash) {
		t.Errorf("Verify() with empty hash, error = %v, want ErrEmptyHash", err)
	}
}

// --- Empty password ---

func TestHash_EmptyPassword(t *testing.T) {
	svc := newTestService(t)

	_, err := svc.Hash("")
	if !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Hash(\"\") error = %v, want ErrEmptyPassword", err)
	}
}

func TestVerify_EmptyPassword(t *testing.T) {
	svc := newTestService(t)

	encoded, err := svc.Hash("some-real-password")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	match, err := svc.Verify("", encoded)
	if !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Verify(\"\", ...) error = %v, want ErrEmptyPassword", err)
	}
	if match {
		t.Error("Verify(\"\", ...) = true, want false")
	}
}

// --- Password length guard ---

func TestHash_PasswordTooLong(t *testing.T) {
	svc := newTestService(t)
	tooLong := strings.Repeat("a", maxPasswordLength+1)

	_, err := svc.Hash(tooLong)
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("Hash() with an over-long password, error = %v, want ErrPasswordTooLong", err)
	}
}

func TestHash_PasswordAtMaxLengthSucceeds(t *testing.T) {
	svc := newTestService(t)
	atLimit := strings.Repeat("a", maxPasswordLength)

	if _, err := svc.Hash(atLimit); err != nil {
		t.Errorf("Hash() with a password exactly at the length limit, error = %v, want nil", err)
	}
}

// --- Params validation (defense against misconfiguration, not just bad input) ---

func TestNewPasswordService_RejectsInvalidParamsAtHashTime(t *testing.T) {
	svc := NewPasswordService(Params{Memory: 1, Iterations: 1, Parallelism: 4, SaltLength: 16, KeyLength: 32})

	if _, err := svc.Hash("any-password"); err == nil {
		t.Error("Hash() with Memory below the 8*Parallelism floor = nil error, want an error")
	}
}

// --- Malformed hash / fail-safe rather than panic ---

// TestVerify_MalformedInputNeverPanics drives Verify with adversarial
// strings well beyond the structured malformed cases in
// TestVerify_InvalidEncodedHash — very short strings, a lone separator,
// invalid UTF-8, an oversized blob — none of which decodeHash's parser
// was written with in mind. A parser built from strings.Split,
// fmt.Sscanf, and base64 decoding *should* only ever return an error on
// bad input, never panic, but "should" is exactly the gap a test needs to
// close: a future edit to decodeHash (e.g. indexing parts[n] without
// re-checking len(parts)) could silently reintroduce a panic that only
// shows up against input this adversarial, not against well-formed
// wrong-password cases.
func TestVerify_MalformedInputNeverPanics(t *testing.T) {
	svc := newTestService(t)

	adversarial := []string{
		"$",
		"$$",
		"$argon2id$",
		"$argon2id$v=19$",
		"$argon2id$v=19$m=8192,t=1,p=2$",
		"argon2id",
		string([]byte{0xff, 0xfe, 0x00, 0x24, 0x24}), // invalid UTF-8 containing a stray '$'
		strings.Repeat("$", 100),
		strings.Repeat("a", 10_000),
		"$argon2id$v=19$m=8192,t=1,p=2$" + strings.Repeat("A", 10_000) + "$aGFzaA",
	}

	for _, hash := range adversarial {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Verify(_, %q) panicked: %v", hash, r)
				}
			}()
			match, err := svc.Verify("any-password", hash)
			if err == nil {
				t.Errorf("Verify(_, %q) = nil error, want a non-nil error for malformed input", hash)
			}
			if match {
				t.Errorf("Verify(_, %q) = true, want false for malformed input", hash)
			}
		}()
	}
}

// --- Persisted-and-later-verified: the encoded hash is fully self-sufficient ---

// TestVerify_PersistedHashVerifiesUnderDifferentServiceConfiguration
// simulates the realistic lifecycle a stored hash actually goes through:
// created by one process (with whatever Params were in effect that day),
// read back and checked by a different call, potentially after the
// service's *default* configuration has since been strengthened. Using
// two independently constructed PasswordService instances with different
// Params — rather than reusing the instance that produced the hash — is
// what makes this a persistence test rather than a same-process
// round-trip: it proves Verify's behavior depends only on what's encoded
// in the string handed to it, never on any state the service instance
// carries.
func TestVerify_PersistedHashVerifiesUnderDifferentServiceConfiguration(t *testing.T) {
	writer := NewPasswordService(Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	const password = "persisted-across-a-config-change"

	stored, err := writer.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// A different instance, deliberately configured with different
	// Params — standing in for "the service redeployed with new default
	// cost parameters" between when this hash was written and when it's
	// read back.
	reader := NewPasswordService(Params{Memory: 32 * 1024, Iterations: 2, Parallelism: 4, SaltLength: 32, KeyLength: 64})

	match, err := reader.Verify(password, stored)
	if err != nil {
		t.Fatalf("Verify() on a hash 'persisted' under different service config, error = %v, want nil", err)
	}
	if !match {
		t.Error("Verify() on a hash 'persisted' under different service config = false, want true")
	}

	// The wrong password must still be rejected under the exact same
	// cross-configuration conditions — a persisted hash isn't a free pass.
	match, err = reader.Verify("not-the-password", stored)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil (a wrong password is not an error)", err)
	}
	if match {
		t.Error("Verify() with the wrong password against a persisted hash = true, want false")
	}
}

// TestVerify_KnownGoldenHash checks a real Argon2id hash computed once,
// ahead of time, and frozen as a literal — not generated by this test
// run. This is the strongest form of "persisted and later verified":
// goldenHash was produced by this same package on one occasion and never
// touched again, exactly like a value sitting untouched in a database
// column since the day a user registered. If a future change to Hash's
// encoding (a field reordered, a separator changed) ever broke
// compatibility with hashes already stored in a real database, this is
// the test that would catch it — the other tests in this file only ever
// verify hashes they just created, so they cannot.
func TestVerify_KnownGoldenHash(t *testing.T) {
	const (
		goldenPassword = "golden-value-test-password"
		goldenHash     = "$argon2id$v=19$m=8192,t=1,p=2$Oz76zhma+OzUa2GahSAcNw$E6NsOBt0sN8q60jMX5+mKnGGA0REElAtx+ySVAzqqPY"
	)
	svc := newTestService(t)

	match, err := svc.Verify(goldenPassword, goldenHash)
	if err != nil {
		t.Fatalf("Verify() against a known-good golden hash, error = %v, want nil", err)
	}
	if !match {
		t.Fatal("Verify() against a known-good golden hash = false, want true — the Argon2id encoding may have changed incompatibly")
	}

	if match, err := svc.Verify("wrong-password", goldenHash); err != nil || match {
		t.Errorf("Verify(\"wrong-password\", goldenHash) = (%v, %v), want (false, nil)", match, err)
	}
}
