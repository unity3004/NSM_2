// Package secrets implements the Secrets Engine's cryptographic core
// (Sprint 3 Phase 2): envelope-encrypting secret values with AES-256-GCM
// before they ever reach PostgreSQL, and decrypting them back. It is
// deliberately narrow and self-contained — like internal/security (see
// that package's own doc comment), it has no dependency on
// internal/entity, internal/repository, any logging package, or net/http.
// That absence is a security property: a package that imports no logger
// cannot be made to log a plaintext secret or a key by a future one-line
// edit. internal/service (a later phase) is where this package's output
// gets handed to repository.SecretRepository.CreateVersion; this package
// itself never touches a database.
//
// This phase implements no REST endpoints, no key rotation, and no
// production key-management provider — only the encryption engine, the
// KeyProvider abstraction, and a development-only KeyProvider
// implementation. See KeyProvider's doc comment for how a real KMS/HSM
// provider would plug in later without EncryptionService changing at all.
package secrets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

// ErrKeyProviderMisconfigured means a KeyProvider was asked to operate
// without valid key material — missing configuration, malformed input, or
// key material of the wrong length. Safe to propagate all the way to a
// log line: it names the category of problem, never the value that
// caused it.
var ErrKeyProviderMisconfigured = errors.New("secrets: key provider is not configured with valid key material")

// ErrKeyNotFound means no key exists for a requested key identifier —
// e.g. decrypting a row whose key_id names a key that has since been
// deleted or was never known to this provider.
var ErrKeyNotFound = errors.New("secrets: no key exists for the given key identifier")

// KeyProvider is the seam between EncryptionService and wherever the
// key-encrypting key (KEK) actually lives. EncryptionService never talks
// to AWS KMS, Azure Key Vault, GCP KMS, or an HSM directly — it only ever
// calls this interface, so a production deployment can supply any of
// those (each as its own KeyProvider implementation, none built in this
// phase) without EncryptionService's code changing at all.
//
// Both methods return raw key bytes because that mirrors how envelope
// encryption actually works even against a real KMS: AWS KMS's own
// GenerateDataKey API, for example, returns a plaintext data key
// alongside its KMS-encrypted form for exactly this reason — the caller
// uses the plaintext key locally for AES-GCM and discards it immediately
// afterward. Nothing above EncryptionService in this codebase ever sees
// this return value; it never crosses a service boundary, is never
// logged, and is never included in an API response — see
// EncryptionService's own handling for where that boundary is enforced.
type KeyProvider interface {
	// GetCurrentKey returns the key that should encrypt new data right
	// now, and the opaque identifier that names it. The identifier is
	// what EncryptionService stores in secret_versions.key_id, so a later
	// GetKey call — or a human reading that column — can find this exact
	// key again even after CurrentKey has moved on to a newer one.
	GetCurrentKey(ctx context.Context) (key []byte, keyID string, err error)
	// GetKey returns the specific key keyID names — used to decrypt data
	// that isn't necessarily under the current key anymore. Returns
	// ErrKeyNotFound if no key with that identifier is known.
	GetKey(ctx context.Context, keyID string) (key []byte, err error)
}

// KeyGenerator is an optional capability a KeyProvider MAY also
// implement, for providers that can mint their own fresh key material
// and identifier on demand — DevKeyProvider does (see GenerateKey); a
// real KMS/HSM-backed KeyProvider is not expected to (see DevKeyProvider's
// own doc comment). Provisioning a new production key remains a
// deliberate, out-of-band operator action — see
// NSM/key-management-architecture.md §7 — never something this codebase
// automates end-to-end for a real deployment. Kept as a separate
// interface from KeyProvider itself, rather than a third KeyProvider
// method, so a KMS-backed implementation is never forced to either
// implement it or explain why it doesn't: EncryptionService and
// KeyManager depend only on KeyProvider, never on this.
type KeyGenerator interface {
	// GenerateKey mints fresh, random key material, registers it under a
	// new identifier, and returns that identifier. The caller (see
	// service.KeyRotationService.RotateToNewKey) is then expected to
	// activate it through the normal KeyManager.Rotate path, exactly as
	// if an operator had provisioned the key out-of-band and handed over
	// its ID.
	GenerateKey(ctx context.Context) (keyID string, err error)
}

// devKeyLength is AES-256's key length in bytes.
const devKeyLength = 32

// DevKeyProvider is a KeyProvider backed by AES-256 key material supplied
// in-process — one key at construction, from configuration
// (config.SecretsConfig.DevMasterKey — sourced via
// AUTH_SECRETS_DEV_MASTER_KEY, following the exact same "never a literal
// in source" convention as jwt.signing_key and access_token.private_key_pem),
// plus, since Sprint 4 Task 1b, any number of additional keys registered
// afterward via AddKey — so that KeyManager.Rotate has real (if
// dev-grade) key material to rotate to when it is exercised against this
// provider directly, rather than only against a test-only fake. Rotating
// through KeyManager never asks this provider to change its own idea of
// "current" — see GetCurrentKey's own doc comment for why AddKey alone is
// sufficient.
//
// DEVELOPMENT ONLY. This is not equivalent to a production KMS/HSM in any
// respect: every key is held in this process's memory for its entire
// lifetime, none has any access audit trail independent of this
// application's own, and each is only as protected as whatever supplied
// its base64 value (an environment variable, a test literal) — none of a
// real KMS's hardware isolation, access logging, or
// rotation-without-re-encryption properties apply. Never point this at a
// production deployment; see secrets.KeyProvider's own doc comment for
// how a real KMS/HSM-backed implementation plugs in instead, and
// NSM/key-management-architecture.md §7 for the full list of what
// distinguishes this from production key management.
type DevKeyProvider struct {
	mu    sync.RWMutex
	keyID string
	keys  map[string][]byte
}

// NewDevKeyProvider builds a DevKeyProvider from a base64-encoded 256-bit
// key and its identifier — both plain strings, the same shape
// security.LoadSigningKeySet already takes for the access-token signing
// key, so a caller sources them from config.Config exactly the way
// cmd/server/main.go already sources AccessToken.KeyID/PrivateKeyPEM:
// never a hardcoded literal.
//
// Fails closed at construction time, never later as a confusing
// encryption failure: an empty key ID, missing key material, a value
// that isn't valid base64, or one that doesn't decode to exactly 32
// bytes are all rejected here.
func NewDevKeyProvider(keyID, keyBase64 string) (*DevKeyProvider, error) {
	if keyID == "" {
		return nil, fmt.Errorf("secrets: NewDevKeyProvider: key ID is required")
	}
	if keyBase64 == "" {
		return nil, fmt.Errorf("%w: no key material configured (set AUTH_SECRETS_DEV_MASTER_KEY)", ErrKeyProviderMisconfigured)
	}
	key, err := decodeDevKeyMaterial(keyBase64)
	if err != nil {
		return nil, err
	}
	return &DevKeyProvider{keyID: keyID, keys: map[string][]byte{keyID: key}}, nil
}

// AddKey registers an additional key identifier and its material with an
// already-constructed DevKeyProvider — for tests, and for exercising
// KeyManager.Rotate against genuine (if still dev-grade) key material
// instead of only the fakeMultiKeyProvider test double internal/secrets'
// own tests otherwise rely on. Fails closed exactly like
// NewDevKeyProvider: an empty key ID, missing/malformed/wrong-length
// material, or a keyID this provider already knows about are all
// rejected here rather than silently overwriting existing material.
//
// This does not change what GetCurrentKey returns — see that method's
// own doc comment for why that is correct, not a limitation.
func (p *DevKeyProvider) AddKey(keyID, keyBase64 string) error {
	if keyID == "" {
		return fmt.Errorf("secrets: DevKeyProvider.AddKey: key ID is required")
	}
	if keyBase64 == "" {
		return fmt.Errorf("%w: no key material given for key ID %q", ErrKeyProviderMisconfigured, keyID)
	}
	key, err := decodeDevKeyMaterial(keyBase64)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.keys[keyID]; exists {
		return fmt.Errorf("secrets: DevKeyProvider.AddKey: key ID %q is already registered", keyID)
	}
	p.keys[keyID] = key
	return nil
}

// GenerateKey implements KeyGenerator — DEVELOPMENT ONLY, like every
// other DevKeyProvider capability (see this type's own doc comment). It
// mints devKeyLength random bytes via crypto/rand (the same source
// EncryptionService itself uses for DEKs and nonces) under a fresh
// sequential identifier — "key-v1", "key-v2", ... one past the highest
// key-vN this provider currently knows about, the same naming convention
// KeyManager.Rotate's own examples already use. A real KMS assigns its
// own key identifiers (ARNs, resource names) and does not hand back raw
// key bytes for a newly minted key the way this dev-only method does —
// see KeyGenerator's own doc comment for why that capability is not part
// of the core KeyProvider interface.
func (p *DevKeyProvider) GenerateKey(ctx context.Context) (string, error) {
	key := make([]byte, devKeyLength)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("secrets: DevKeyProvider.GenerateKey: generating random key material: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	keyID := p.nextKeyIDLocked()
	if _, exists := p.keys[keyID]; exists {
		// Unreachable in practice (nextKeyIDLocked always picks an ID
		// absent from p.keys) — fails loudly rather than silently
		// overwriting an existing key if it ever somehow happens.
		return "", fmt.Errorf("secrets: DevKeyProvider.GenerateKey: generated ID %q collides with an existing key", keyID)
	}
	p.keys[keyID] = key
	return keyID, nil
}

// nextKeyIDLocked returns "key-vN" for the smallest N not already present
// in p.keys — callers must hold p.mu. Scans existing IDs rather than
// keeping a separate counter, so it stays correct even when AddKey was
// used directly (bypassing GenerateKey) to register a key out of
// sequence, or with an ID that doesn't fit the key-vN shape at all (those
// are simply ignored by the scan).
func (p *DevKeyProvider) nextKeyIDLocked() string {
	max := 0
	for id := range p.keys {
		var n int
		if _, err := fmt.Sscanf(id, "key-v%d", &n); err == nil && n > max {
			max = n
		}
	}
	return fmt.Sprintf("key-v%d", max+1)
}

// decodeDevKeyMaterial validates and decodes a base64-encoded key value —
// the shared shape check both NewDevKeyProvider and AddKey enforce, so
// there is exactly one place that defines "what a valid dev key looks
// like" to audit or extend.
func decodeDevKeyMaterial(keyBase64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("%w: key is not valid base64", ErrKeyProviderMisconfigured)
	}
	if len(key) != devKeyLength {
		return nil, fmt.Errorf("%w: key must decode to exactly %d bytes (256 bits), got %d", ErrKeyProviderMisconfigured, devKeyLength, len(key))
	}
	return key, nil
}

// GetCurrentKey implements KeyProvider. Always returns the one key this
// provider was originally *constructed* with, regardless of how many
// more have since been registered via AddKey — this is correct, not a
// limitation: KeyManager.GetCurrentKey only ever calls a provider's
// GetCurrentKey once, during first-ever bootstrap (see
// KeyManager.bootstrapFromProvider), to learn the very first ACTIVE key.
// Every later call — including the provider's view of "current" after
// KeyManager.Rotate — resolves through KeyManager's own encryption_keys
// metadata instead, via GetKey(ctx, thatSpecificID), never by re-asking
// the provider what is current. A DevKeyProvider therefore never needs
// its own mutable "current key" concept for rotation to work correctly.
func (p *DevKeyProvider) GetCurrentKey(ctx context.Context) ([]byte, string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.copyKeyLocked(p.keyID), p.keyID, nil
}

// GetKey implements KeyProvider — resolves any key this provider was
// constructed with or has since had registered via AddKey.
func (p *DevKeyProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	key, ok := p.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return copyKeyBytes(key), nil
}

// copyKeyLocked is copyKeyBytes for a key already known to be in p.keys —
// callers must hold p.mu.
func (p *DevKeyProvider) copyKeyLocked(keyID string) []byte {
	return copyKeyBytes(p.keys[keyID])
}

// copyKeyBytes returns a fresh copy of key rather than a reference to its
// own backing array — so a caller zeroing its copy after use (see
// EncryptionService) can never zero out this provider's only copy out
// from under a concurrent or later call.
func copyKeyBytes(key []byte) []byte {
	k := make([]byte, len(key))
	copy(k, key)
	return k
}

// Compile-time proof that DevKeyProvider satisfies both interfaces —
// GenerateKey is genuinely optional (KeyGenerator is never required by
// KeyProvider itself), but DevKeyProvider always implements it.
var (
	_ KeyProvider  = (*DevKeyProvider)(nil)
	_ KeyGenerator = (*DevKeyProvider)(nil)
)
