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
	"encoding/base64"
	"errors"
	"fmt"
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

// devKeyLength is AES-256's key length in bytes.
const devKeyLength = 32

// DevKeyProvider is a KeyProvider backed by a single AES-256 key supplied
// once, at construction, from configuration (config.SecretsConfig.DevMasterKey
// — sourced via AUTH_SECRETS_DEV_MASTER_KEY, following the exact same
// "never a literal in source" convention as jwt.signing_key and
// access_token.private_key_pem).
//
// DEVELOPMENT ONLY. This is not equivalent to a production KMS/HSM in any
// respect: the key is held in this process's memory for its entire
// lifetime, is never rotated, has no access audit trail, and is only as
// protected as whatever holds the environment variable it came from —
// none of a real KMS's hardware isolation, access logging, or
// rotation-without-re-encryption properties apply. Never point this at a
// production deployment.
type DevKeyProvider struct {
	keyID string
	key   []byte
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
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("%w: key is not valid base64", ErrKeyProviderMisconfigured)
	}
	if len(key) != devKeyLength {
		return nil, fmt.Errorf("%w: key must decode to exactly %d bytes (256 bits), got %d", ErrKeyProviderMisconfigured, devKeyLength, len(key))
	}
	return &DevKeyProvider{keyID: keyID, key: key}, nil
}

// GetCurrentKey implements KeyProvider. DevKeyProvider has exactly one
// key, so this always returns it — there is no rotation to choose
// between candidates from.
func (p *DevKeyProvider) GetCurrentKey(ctx context.Context) ([]byte, string, error) {
	return p.copyKey(), p.keyID, nil
}

// GetKey implements KeyProvider.
func (p *DevKeyProvider) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	if keyID != p.keyID {
		return nil, ErrKeyNotFound
	}
	return p.copyKey(), nil
}

// copyKey returns a fresh copy of the provider's key material rather than
// a reference to its own backing array — so a caller zeroing its copy
// after use (see EncryptionService) can never zero out this provider's
// only copy out from under a concurrent or later call.
func (p *DevKeyProvider) copyKey() []byte {
	k := make([]byte, len(p.key))
	copy(k, p.key)
	return k
}
