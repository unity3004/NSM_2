package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// AlgorithmAES256GCM is the only algorithm this phase implements, and the
// exact value EncryptedPayload.Algorithm / secret_versions.algorithm
// carries for it. Stored per-row (not assumed globally) so a future
// second algorithm can be told apart from this one in-band, per row,
// without a schema change — see Decrypt's algorithm check.
const AlgorithmAES256GCM = "AES-256-GCM"

// dekLength is AES-256's key length in bytes — both the per-operation
// data-encryption key (DEK) and the key-encrypting key (KEK) a KeyProvider
// returns must be exactly this long.
const dekLength = 32

// Sentinel errors every Encrypt/Decrypt failure resolves to. These are
// the categories the ERROR HANDLING requirement asks for — key
// unavailable, malformed ciphertext, unsupported algorithm — deliberately
// coarse-grained on the ciphertext/authentication side: whether a
// decryption failed because the ciphertext was corrupted, the nonce was
// wrong, or the authentication tag didn't match are all reported as the
// single ErrCiphertextInvalid. Go's crypto/cipher.AEAD.Open doesn't
// distinguish these cases either (by design — see its doc comment), and
// even if it did, surfacing which one happened would hand an attacker
// a free oracle for probing ciphertext malleability. "Authentication
// failed" is the only safe thing to say.
var (
	ErrKeyUnavailable       = errors.New("secrets: encryption key is unavailable")
	ErrCiphertextInvalid    = errors.New("secrets: ciphertext failed authentication or is malformed")
	ErrUnsupportedAlgorithm = errors.New("secrets: unsupported encryption algorithm")
)

// EncryptContext names the secret_versions row an encryption or
// decryption operates on. Its fields are folded into AES-GCM's additional
// authenticated data (see buildContextAAD) so that an attacker with only
// UPDATE access to secret_versions — able to rewrite ciphertext, nonce,
// auth_tag, wrapped_dek, and key_id together, copied verbatim from a
// different row — cannot make one secret's encrypted value silently
// decrypt successfully under a different secret's identity. Without this
// binding, GCM's authentication alone only proves "this ciphertext was
// produced by someone holding the DEK" — it says nothing about which
// secret_id/version that DEK was ever supposed to belong to, because a
// full-row copy carries its own (genuinely valid) DEK-wrapping right
// along with it. Binding SecretID and Version into the AAD means the
// authentication tag itself encodes "and this is secret X's version Y" —
// moving the row anywhere else makes the tag stop matching.
type EncryptContext struct {
	SecretID string
	Version  int
}

func (ec EncryptContext) validate() error {
	if ec.SecretID == "" {
		return fmt.Errorf("secrets: EncryptContext.SecretID is required")
	}
	if ec.Version <= 0 {
		return fmt.Errorf("secrets: EncryptContext.Version must be positive")
	}
	return nil
}

// EncryptedPayload is everything secret_versions needs to store for a
// value to be decryptable later, and nothing more — there is deliberately
// no plaintext-shaped field anywhere on this type. Field-for-field, it
// maps directly onto entity.SecretVersion's own encryption columns
// (internal/entity/secret.go, Phase 1): Ciphertext, Nonce, AuthTag,
// WrappedDEK, KeyID, Algorithm. This package does not import
// internal/entity itself (see the package doc comment on why); the
// mapping is proven by test/integration/secret_encryption_test.go, which
// round-trips a real EncryptedPayload through the real
// repository.SecretRepository from Phase 1 against a real database.
type EncryptedPayload struct {
	// Ciphertext is the secret value, AES-256-GCM-sealed under a fresh,
	// random, single-use DEK — GCM's authentication tag has been split
	// off into AuthTag (see sealSplit), matching secret_versions' two
	// separate columns.
	Ciphertext []byte
	// Nonce is the DEK-level nonce Ciphertext was sealed under. A fresh
	// nonce is generated for every single Encrypt call (see Encrypt) —
	// never reused, never derived from a timestamp or counter. See the
	// package doc comment's "NONCE REQUIREMENTS" discussion for why reuse
	// under the same key is a catastrophic failure for GCM specifically
	// (it allows recovering the authentication subkey and forging
	// ciphertexts, not merely leaking equality between two plaintexts the
	// way nonce reuse does for most other stream-cipher-based schemes).
	Nonce []byte
	// AuthTag is GCM's authentication tag, split out of Seal's combined
	// output — see sealSplit.
	AuthTag []byte
	// WrappedDEK is the one-time DEK that sealed Ciphertext, itself
	// AES-256-GCM-sealed under KeyID's key: nonce || ciphertext || tag,
	// self-contained so unwrapping needs nothing but this field and the
	// KEK named by KeyID. This is what makes key rotation possible without
	// touching Ciphertext at all — see the package doc comment's "KEY
	// ROTATION DESIGN" discussion.
	WrappedDEK []byte
	// KeyID names which KeyProvider key wrapped WrappedDEK — stored so a
	// future GetKey(ctx, KeyID) call can find the right key again even
	// after the provider's current key has moved on.
	KeyID string
	// Algorithm is AlgorithmAES256GCM today. Decrypt refuses to process a
	// payload whose Algorithm it doesn't recognize (see ErrUnsupportedAlgorithm)
	// rather than guessing.
	Algorithm string
}

// String implements fmt.Stringer with a safe, non-sensitive summary —
// deliberately overriding the default struct formatting, which would
// otherwise print Ciphertext/Nonce/AuthTag/WrappedDEK's raw bytes if
// anything ever did fmt.Sprintf("%v", payload), log.Print(payload), or
// similar. Even KeyID, which is not itself secret, reveals nothing about
// the key's material — only its identifier.
func (p *EncryptedPayload) String() string {
	return fmt.Sprintf("EncryptedPayload{KeyID: %q, Algorithm: %q, CiphertextLen: %d}", p.KeyID, p.Algorithm, len(p.Ciphertext))
}

// EncryptionService turns plaintext secret values into EncryptedPayloads
// and back, using AES-256-GCM — crypto/aes and crypto/cipher from the Go
// standard library, no custom cryptography anywhere in this package —
// under a fresh, single-use, envelope-encrypted DEK per operation.
//
// It never persists anything itself: internal/service.SecretService (a
// later phase, not built yet) is responsible for handing an
// EncryptedPayload's fields to repository.SecretRepository.CreateVersion,
// and for never retaining or logging the plaintext this service handed it
// — see the package doc comment on why EncryptionService itself cannot
// even try to enforce that (it has no logging dependency to misuse, and
// once it returns plaintext to a caller, that caller's handling of it is
// outside this type's control).
type EncryptionService struct {
	keys KeyProvider
}

// NewEncryptionService constructs an EncryptionService backed by keys.
// Swapping a DevKeyProvider for a production KMS-backed KeyProvider later
// requires no change here — see KeyProvider's own doc comment.
func NewEncryptionService(keys KeyProvider) *EncryptionService {
	return &EncryptionService{keys: keys}
}

// Encrypt seals plaintext into an EncryptedPayload. ec identifies which
// secret and version this ciphertext will belong to — see EncryptContext's
// doc comment for why that binding matters.
//
// plaintext is never retained by this method beyond the call: no field on
// EncryptionService holds it, no package-level variable holds it, and it
// is not copied except for the one copy AES-GCM's Seal itself produces
// (its ciphertext output) — see the package doc comment's "MEMORY"
// discussion for what this codebase can and cannot guarantee about that.
func (s *EncryptionService) Encrypt(ctx context.Context, plaintext []byte, ec EncryptContext) (payload *EncryptedPayload, err error) {
	if err := ec.validate(); err != nil {
		return nil, err
	}

	kek, keyID, err := s.keys.GetCurrentKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	defer zero(kek)
	if len(kek) != dekLength {
		return nil, fmt.Errorf("%w: key provider returned a key of length %d, want %d", ErrKeyUnavailable, len(kek), dekLength)
	}

	dek := make([]byte, dekLength)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("secrets: generating data encryption key: %w", err)
	}
	defer zero(dek)

	dataAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, dataAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secrets: generating nonce: %w", err)
	}
	ciphertext, tag := sealSplit(dataAEAD, nonce, plaintext, buildContextAAD(ec.SecretID, ec.Version, keyID))

	wrapAEAD, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	wrapNonce := make([]byte, wrapAEAD.NonceSize())
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, fmt.Errorf("secrets: generating DEK-wrap nonce: %w", err)
	}
	wrappedSealed := wrapAEAD.Seal(nil, wrapNonce, dek, buildKeyAAD(keyID))
	wrappedDEK := concatBytes(wrapNonce, wrappedSealed)

	return &EncryptedPayload{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AuthTag:    tag,
		WrappedDEK: wrappedDEK,
		KeyID:      keyID,
		Algorithm:  AlgorithmAES256GCM,
	}, nil
}

// Decrypt authenticates and opens payload, returning the original
// plaintext only if every check passes: the algorithm is recognized, the
// named key is available, the wrapped DEK authenticates and unwraps under
// that key, and the ciphertext authenticates under the unwrapped DEK and
// ec's AAD binding. Any failure returns one of this package's sentinel
// errors (see their doc comments) and a nil plaintext — never a partial
// or corrupted result.
//
// ec must name the same secret_id/version the payload was originally
// encrypted for (see EncryptContext's doc comment) — passing the wrong
// one is indistinguishable, by design, from tampered ciphertext:
// authentication fails either way.
func (s *EncryptionService) Decrypt(ctx context.Context, payload *EncryptedPayload, ec EncryptContext) (plaintext []byte, err error) {
	if payload == nil {
		return nil, fmt.Errorf("secrets: Decrypt: payload is required")
	}
	if payload.Algorithm != AlgorithmAES256GCM {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, payload.Algorithm)
	}
	if err := ec.validate(); err != nil {
		return nil, err
	}

	kek, err := s.keys.GetKey(ctx, payload.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	defer zero(kek)
	if len(kek) != dekLength {
		return nil, fmt.Errorf("%w: stored key has an invalid length", ErrKeyUnavailable)
	}

	wrapAEAD, err := newAEAD(kek)
	if err != nil {
		return nil, err
	}
	if len(payload.WrappedDEK) < wrapAEAD.NonceSize() {
		return nil, ErrCiphertextInvalid
	}
	wrapNonce, wrappedSealed := payload.WrappedDEK[:wrapAEAD.NonceSize()], payload.WrappedDEK[wrapAEAD.NonceSize():]
	dek, err := wrapAEAD.Open(nil, wrapNonce, wrappedSealed, buildKeyAAD(payload.KeyID))
	if err != nil {
		return nil, ErrCiphertextInvalid
	}
	defer zero(dek)

	dataAEAD, err := newAEAD(dek)
	if err != nil {
		return nil, err
	}
	sealed := concatBytes(payload.Ciphertext, payload.AuthTag)
	plaintext, err = dataAEAD.Open(nil, payload.Nonce, sealed, buildContextAAD(ec.SecretID, ec.Version, payload.KeyID))
	if err != nil {
		return nil, ErrCiphertextInvalid
	}
	return plaintext, nil
}

// newAEAD builds an AES-256-GCM cipher.AEAD from a 32-byte key — the one
// place both Encrypt and Decrypt construct one, so there is exactly one
// call to aes.NewCipher / cipher.NewGCM in this package to audit.
// cipher.NewGCM's default nonce size (12 bytes / 96 bits, per NIST SP
// 800-38D) is used throughout; nothing in this package calls
// NewGCMWithNonceSize.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: constructing AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: constructing GCM: %w", err)
	}
	return gcm, nil
}

// sealSplit seals plaintext and splits GCM's combined Seal output into
// (ciphertext, tag) — Go's standard library has no API that returns them
// separately, but secret_versions (Phase 1) models them as two columns
// per the architecture review, so this is the one place that split
// happens. aead.Overhead() (16 bytes for GCM) is used rather than a
// hardcoded constant, so this stays correct if this package ever supports
// a second AEAD with a different tag size.
func sealSplit(aead cipher.AEAD, nonce, plaintext, aad []byte) (ciphertext, tag []byte) {
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	n := len(sealed) - aead.Overhead()
	return sealed[:n], sealed[n:]
}

// concatBytes always allocates a fresh backing array for its result —
// unlike append(a, b...), which can silently write into a's backing array
// if it happens to have spare capacity. Used everywhere this package
// reassembles two stored byte slices (ciphertext+tag, nonce+wrapped DEK)
// into one buffer to hand to crypto/cipher, so that operation can never
// alias — and therefore never risk mutating — an EncryptedPayload's own
// stored fields.
func concatBytes(parts ...[]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// buildContextAAD and buildKeyAAD both use appendField's explicit
// length-prefixing rather than plain concatenation — without it,
// SecretID="ab"+KeyID="c" and SecretID="a"+KeyID="bc" would authenticate
// identically, letting a boundary shift between fields slip past GCM's
// authentication the same way an unbound AAD would. Every field is framed
// unambiguously instead.

// buildContextAAD is the additional authenticated data bound to a secret
// value's own encryption — see EncryptContext's doc comment for what
// attack this defends against and why SecretID, Version, and KeyID
// specifically are the fields chosen (identity + version pin the
// ciphertext to one specific row; KeyID additionally ties it to the key
// that was current when it was written, so key_id itself can't be
// silently swapped out from under an already-encrypted row).
func buildContextAAD(secretID string, version int, keyID string) []byte {
	var versionBytes [4]byte
	binary.BigEndian.PutUint32(versionBytes[:], uint32(version))
	var buf []byte
	buf = appendField(buf, []byte(secretID))
	buf = appendField(buf, versionBytes[:])
	buf = appendField(buf, []byte(keyID))
	return buf
}

// buildKeyAAD is the additional authenticated data bound to a DEK's own
// wrapping under a KEK — binding keyID means an unwrap only succeeds if
// the wrapped blob claims to have been wrapped by exactly the key
// performing the unwrap, defense-in-depth on top of GetKey's own
// identifier-based lookup.
func buildKeyAAD(keyID string) []byte {
	return appendField(nil, []byte(keyID))
}

func appendField(buf, field []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	buf = append(buf, length[:]...)
	buf = append(buf, field...)
	return buf
}

// zero best-effort overwrites b with zeros before it becomes garbage —
// defense-in-depth, not a guarantee. Go's runtime can have already copied
// these bytes elsewhere (escape analysis moving a value between stack and
// heap, a slice growth reallocation, the garbage collector itself) before
// this call ever runs, and the OS can have paged the memory holding them
// out to swap at any point. This is deliberately not claimed as secure
// erasure anywhere in this package's documentation — see the package doc
// comment's "MEMORY" discussion. It is still strictly better than doing
// nothing: it closes the specific, common window where a stale DEK or KEK
// sits readable in a live heap allocation for the remainder of the
// process's life after this function's caller is done with it.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
