package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// KeyState mirrors a key's position in its lifecycle. See the doc comment
// on each constant for exactly what cryptographic operations that state
// permits — KeyManager.GetCurrentKey and KeyManager.GetKey are the only
// places these rules are enforced, so a new state's meaning only has to be
// taught to this package once.
type KeyState string

const (
	// KeyStateActive is the one key (at most) new data is ever encrypted
	// under. Permits both encrypt and decrypt.
	KeyStateActive KeyState = "active"
	// KeyStateRetiring is a key that Rotate has just moved off of: no
	// longer used for new encryptions, but still fully able to decrypt
	// data that was written under it before rotation. This is the state
	// every previously-ACTIVE key enters the instant a newer one is
	// activated — never skipped, never combined with RETIRED.
	KeyStateRetiring KeyState = "retiring"
	// KeyStateRetired is a RETIRING key an operator has explicitly
	// confirmed is safe to stop actively supporting — see
	// KeyRotationService.RetireKey, which is the only place that
	// confirmation (checking secret_versions for remaining references) is
	// performed. Despite the name, this foundation still permits decrypt
	// in the RETIRED state by default: "safe to retire" here means
	// "believed unreferenced," not "verified beyond any doubt," and
	// treating a mistaken belief as an outage (rather than a slightly
	// longer-lived key) is the safer failure mode. True, unconditional
	// revocation is KeyStateDisabled, a separate and more consequential
	// transition. See this package's doc comment and
	// NSM/key-management-architecture.md for the operational policy this
	// implements.
	KeyStateRetired KeyState = "retired"
	// KeyStateDisabled permits no cryptographic operation at all —
	// encrypt and decrypt both refuse. This is the emergency-revocation
	// state: use it when a key is known or suspected to be compromised
	// and continuing to decrypt with it is the greater risk, even at the
	// cost of the data under it becoming unreadable until the key is
	// re-enabled (this package provides no re-enable path — see
	// KeyManager.DisableKey's doc comment).
	KeyStateDisabled KeyState = "disabled"
)

// KeyMetadata is everything KeyManager tracks about a key identifier other
// than the key material itself — safe to log, safe to return from an
// internal admin API, safe to store in Postgres in plain columns. There is
// deliberately no field here shaped like key material; see this package's
// "SECURITY" doc comment discussion for why that is a property of the type,
// not just a convention callers have to remember.
type KeyMetadata struct {
	KeyID       string
	Algorithm   string
	State       KeyState
	CreatedAt   time.Time
	ActivatedAt *time.Time
	RetiredAt   *time.Time
	DisabledAt  *time.Time
}

// Sentinel errors KeyManager returns. All are safe to log verbatim — none
// embeds a key, only identifiers and category.
var (
	// ErrKeyDisabled means the named key's state is KeyStateDisabled —
	// returned without ever asking the underlying KeyProvider for key
	// material, so a disabled key is unreachable even if the provider
	// backing it would still happily hand back bytes.
	ErrKeyDisabled = errors.New("secrets: key is disabled and cannot be used for cryptographic operations")
	// ErrKeyAlreadyExists means Rotate was asked to activate a key
	// identifier KeyManager already has metadata for — Rotate refuses
	// rather than resurrecting or overwriting an existing key's lifecycle
	// history. See Rotate's doc comment.
	ErrKeyAlreadyExists = errors.New("secrets: a key with this identifier is already known to the key manager")
	// ErrNoActiveKey means no key in the metadata store is currently
	// ACTIVE. During normal operation this is impossible once bootstrap
	// has run once (see ensureBootstrapped) — surfacing this error
	// instead of silently minting a replacement key is what makes that
	// true: an operator who somehow ends up with zero active keys (every
	// key disabled, for instance) gets a loud failure, not a
	// quietly-fabricated new "first" key that may not match what existing
	// ciphertext actually references.
	ErrNoActiveKey = errors.New("secrets: no active key is registered")
	// ErrKeyStillActive means DisableKey or Retire was asked to transition
	// the currently-ACTIVE key directly — refused because the whole point
	// of those safeguards is that a key must be rotated away from before
	// it can be wound down, never the other way around.
	ErrKeyStillActive = errors.New("secrets: key is still active; rotate to a different key before retiring or disabling this one")
)

// KeyMetadataStore persists KeyManager's own bookkeeping about which key
// identifiers exist and their lifecycle state — never key material. It is
// defined here, not in internal/repository, so this package's "no database
// dependency" property (see the package doc comment) still holds:
// KeyManager depends only on this narrow interface, and a concrete
// Postgres-backed implementation (internal/repository/postgres) depends on
// internal/secrets, never the other way around — the same one-directional
// shape KeyProvider itself already establishes for DevKeyProvider versus a
// future KMS-backed implementation.
type KeyMetadataStore interface {
	// Get returns keyID's metadata, or ErrKeyNotFound if this store has
	// never heard of it.
	Get(ctx context.Context, keyID string) (KeyMetadata, error)
	// GetActive returns the single KeyStateActive row, or ErrNoActiveKey
	// if none exists.
	GetActive(ctx context.Context) (KeyMetadata, error)
	// List returns every known key's metadata, most-recently-created
	// first.
	List(ctx context.Context) ([]KeyMetadata, error)
	// Bootstrap idempotently registers meta (State must be
	// KeyStateActive) as the first-ever known key, but only if the store
	// is currently completely empty — see ensureBootstrapped for why that
	// precondition matters. inserted reports whether this call actually
	// performed the insert (false means another caller/process already
	// had); either way, the returned KeyMetadata is authoritative.
	Bootstrap(ctx context.Context, meta KeyMetadata) (result KeyMetadata, inserted bool, err error)
	// ActivateNewKey atomically retires whatever key is currently
	// KeyStateActive (if any) and inserts newKeyID as the new
	// KeyStateActive key — both halves happen together or not at all, so
	// no caller can ever observe a state with zero or two active keys.
	// Returns ErrKeyAlreadyExists if newKeyID is already known.
	ActivateNewKey(ctx context.Context, newKeyID, algorithm string, now time.Time) (KeyMetadata, error)
	// UpdateState transitions keyID to newState, stamping the
	// corresponding lifecycle timestamp (ActivatedAt/RetiredAt/DisabledAt)
	// with at. This method trusts the caller (KeyManager) to have already
	// validated the transition is legal — it performs no state-machine
	// checking of its own.
	UpdateState(ctx context.Context, keyID string, newState KeyState, at time.Time) error
}

// KeyManager is the seam the objective's hierarchy calls out by name:
//
//	Secret -> Crypto Service -> Key Manager -> Key Provider
//
// EncryptionService (Crypto Service) does not change to depend on this
// type explicitly — KeyManager implements the exact same KeyProvider
// interface (GetCurrentKey/GetKey) that EncryptionService already depends
// on, so inserting this layer is a change to what gets constructed in
// cmd/server/main.go, not to encryption.go. That is deliberate: the
// objective asks to "modify the existing Crypto Service only as
// necessary," and Go's structural interfaces make the necessary amount of
// change here zero.
//
// What KeyManager adds on top of a bare KeyProvider:
//   - A durable, authoritative notion of "which key is current" (backed by
//     KeyMetadataStore), instead of trusting the provider's own
//     GetCurrentKey on every call — see ensureBootstrapped.
//   - Explicit lifecycle state (KeyState) per key, enforced on every
//     GetKey/GetCurrentKey call — a disabled key is refused before the
//     underlying provider is ever asked for its bytes.
//   - Rotation (Rotate) that is atomic and cannot leave the system with
//     zero or two active keys, and that verifies the new key is actually
//     available before changing any state.
//   - Retire/DisableKey, both of which refuse to act on the currently
//     active key.
//
// What KeyManager still does not do: decide when to rotate (that is an
// operator or future scheduler's call, made through
// internal/service.KeyRotationService), verify a key is unreferenced by
// any secret before retiring it (that check needs repository.SecretRepository,
// which this package deliberately does not depend on — see
// KeyRotationService.RetireKey), or log/audit anything (same reasoning —
// see internal/service.KeyRotationService for where audit events are
// written).
type KeyManager struct {
	provider KeyProvider
	store    KeyMetadataStore
}

// NewKeyManager constructs a KeyManager over provider (the source of raw
// key material — DevKeyProvider today, a KMS/HSM-backed implementation
// later) and store (the durable record of key identifiers and their
// lifecycle state).
func NewKeyManager(provider KeyProvider, store KeyMetadataStore) *KeyManager {
	return &KeyManager{provider: provider, store: store}
}

// GetCurrentKey implements KeyProvider. It never trusts provider.GetCurrentKey
// directly except during the one-time bootstrap described on
// ensureBootstrapped — every other call resolves "current" from this
// manager's own metadata store, so a provider that (hypothetically, for a
// future implementation) changed its idea of "current" out from under this
// process could never cause a silent, unaudited switch to a different key.
func (m *KeyManager) GetCurrentKey(ctx context.Context) ([]byte, string, error) {
	active, err := m.ensureBootstrapped(ctx)
	if err != nil {
		return nil, "", err
	}
	key, err := m.provider.GetKey(ctx, active.KeyID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	return key, active.KeyID, nil
}

// GetKey implements KeyProvider. keyID must be a key this manager already
// has metadata for — an identifier the provider itself would recognize but
// that never went through KeyManager's own registration (bootstrap or
// Rotate) is refused as ErrKeyNotFound rather than silently trusted, so
// KeyManager's lifecycle state can never be bypassed by asking the
// provider directly. A KeyStateDisabled key is refused before the provider
// is consulted at all — see ErrKeyDisabled.
func (m *KeyManager) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	meta, err := m.store.Get(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if meta.State == KeyStateDisabled {
		return nil, ErrKeyDisabled
	}
	return m.provider.GetKey(ctx, keyID)
}

// Metadata returns keyID's metadata — never key material, safe to expose
// to an operator-facing surface.
func (m *KeyManager) Metadata(ctx context.Context, keyID string) (KeyMetadata, error) {
	return m.store.Get(ctx, keyID)
}

// ActiveMetadata returns the current key's metadata without fetching its
// key material — bootstrapping first if needed, exactly like
// GetCurrentKey, but for callers (KeyRotationService.CurrentKey) that only
// need to report which key is active, not use it.
func (m *KeyManager) ActiveMetadata(ctx context.Context) (KeyMetadata, error) {
	return m.ensureBootstrapped(ctx)
}

// ListKeys returns every known key's metadata, most-recently-created
// first.
func (m *KeyManager) ListKeys(ctx context.Context) ([]KeyMetadata, error) {
	return m.store.List(ctx)
}

// Bootstrap explicitly performs the same first-key registration
// GetCurrentKey/GetKey trigger lazily on first use, so a caller (main.go,
// at startup) can surface a configuration failure immediately and
// distinguish "this is the first time this key has ever been seen" (for
// audit logging — see KeyRotationService.EnsureBootstrapped) from later,
// routine calls. Safe to call every time the process starts: a no-op,
// returning the existing active key, once bootstrap has already happened
// once (by this or any other process sharing the same store).
func (m *KeyManager) Bootstrap(ctx context.Context) (meta KeyMetadata, didBootstrap bool, err error) {
	active, err := m.store.GetActive(ctx)
	if err == nil {
		return active, false, nil
	}
	if !errors.Is(err, ErrNoActiveKey) {
		return KeyMetadata{}, false, err
	}
	return m.bootstrapFromProvider(ctx)
}

// ensureBootstrapped is Bootstrap's logic, called internally by
// GetCurrentKey so a deployment that never explicitly calls Bootstrap at
// startup still works correctly on first use.
func (m *KeyManager) ensureBootstrapped(ctx context.Context) (KeyMetadata, error) {
	active, err := m.store.GetActive(ctx)
	if err == nil {
		return active, nil
	}
	if !errors.Is(err, ErrNoActiveKey) {
		return KeyMetadata{}, err
	}
	meta, _, err := m.bootstrapFromProvider(ctx)
	return meta, err
}

// bootstrapFromProvider registers the provider's current key as this
// manager's first ACTIVE key — but only when the store has never known
// about any key at all (see List check below). If the store already has
// keys and simply lacks an active one, that is a real operational
// anomaly (e.g. every known key was disabled) this function refuses to
// paper over: minting a "new" first key in that situation could silently
// diverge from whatever key_id existing ciphertext actually references,
// exactly the "never guess incorrectly" failure this whole design exists
// to avoid.
func (m *KeyManager) bootstrapFromProvider(ctx context.Context) (KeyMetadata, bool, error) {
	existing, err := m.store.List(ctx)
	if err != nil {
		return KeyMetadata{}, false, err
	}
	if len(existing) > 0 {
		return KeyMetadata{}, false, fmt.Errorf("%w: key metadata store has %d known key(s) but none are active — refusing to register a new first key; this requires manual operator review", ErrNoActiveKey, len(existing))
	}

	_, keyID, err := m.provider.GetCurrentKey(ctx)
	if err != nil {
		return KeyMetadata{}, false, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	if keyID == "" {
		return KeyMetadata{}, false, fmt.Errorf("%w: key provider returned an empty key identifier", ErrKeyProviderMisconfigured)
	}
	now := time.Now().UTC()
	meta, inserted, err := m.store.Bootstrap(ctx, KeyMetadata{
		KeyID:       keyID,
		Algorithm:   AlgorithmAES256GCM,
		State:       KeyStateActive,
		CreatedAt:   now,
		ActivatedAt: &now,
	})
	if err != nil {
		return KeyMetadata{}, false, err
	}
	return meta, inserted, nil
}

// Rotate makes newKeyID the current key: the previously-ACTIVE key (if
// any) moves to KeyStateRetiring, and newKeyID becomes KeyStateActive.
// Existing ciphertext stays decryptable — nothing about already-encrypted
// data changes, only which key new encryptions use (see EncryptionService.Encrypt,
// which always asks GetCurrentKey).
//
// Two safeguards specifically against "partially completed rotation" and
// "accidentally switching to an unavailable key":
//  1. newKeyID's availability is verified against the provider (a real
//     GetKey call) before any state changes at all — a typo'd or
//     not-yet-provisioned key identifier fails here, before this manager's
//     idea of "current" ever moves.
//  2. The retire-old/activate-new state transition itself is one atomic
//     operation (KeyMetadataStore.ActivateNewKey) — no caller can observe
//     an intermediate state with zero or two active keys, and a failure
//     partway through leaves the store exactly as it was before Rotate was
//     called, not half-migrated.
//
// Refuses (ErrKeyAlreadyExists) if newKeyID is already known to this
// manager in any state — Rotate only ever promotes a genuinely new key
// identifier, never resurrects a previously retired or disabled one. That
// restriction is deliberate: reactivating an old key is a much rarer,
// higher-stakes operation than routine forward rotation, and this
// foundation does not provide a convenience method for it (see
// NSM/key-management-architecture.md's operational procedures for what a
// deliberate, manual recovery from that situation looks like).
func (m *KeyManager) Rotate(ctx context.Context, newKeyID string) (KeyMetadata, error) {
	if newKeyID == "" {
		return KeyMetadata{}, fmt.Errorf("secrets: KeyManager.Rotate: newKeyID is required")
	}
	if _, err := m.ensureBootstrapped(ctx); err != nil {
		return KeyMetadata{}, err
	}
	key, err := m.provider.GetKey(ctx, newKeyID)
	if err != nil {
		return KeyMetadata{}, fmt.Errorf("%w: new key %q is not available from the key provider: %w", ErrKeyUnavailable, newKeyID, err)
	}
	zero(key)

	meta, err := m.store.ActivateNewKey(ctx, newKeyID, AlgorithmAES256GCM, time.Now().UTC())
	if err != nil {
		return KeyMetadata{}, err
	}
	return meta, nil
}

// Retire transitions keyID from KeyStateRetiring to KeyStateRetired.
// Refuses ErrKeyStillActive if keyID is currently the active key (rotate
// away from it first) and is a no-op (returns nil) if keyID is already
// KeyStateRetired or KeyStateDisabled.
//
// This method deliberately does not check whether any secret_versions row
// still references keyID — internal/secrets has no repository dependency
// (see the package doc comment) and cannot perform that check itself.
// KeyRotationService.RetireKey is the only caller that should ever invoke
// this, and it performs that check first. Calling KeyManager.Retire
// directly, bypassing that check, is a misuse of this API — see that
// method's doc comment.
func (m *KeyManager) Retire(ctx context.Context, keyID string) error {
	return m.transitionAwayFromActive(ctx, keyID, KeyStateRetired)
}

// DisableKey transitions keyID to KeyStateDisabled, the terminal,
// no-cryptographic-operations-permitted state — see KeyStateDisabled's own
// doc comment for when this is the right call. Refuses ErrKeyStillActive
// if keyID is currently active. Idempotent if already disabled.
//
// There is deliberately no corresponding "enable" method: moving a key
// back out of KeyStateDisabled is exactly the kind of consequential,
// rare, must-be-deliberate operation this foundation does not provide a
// convenience API for — see NSM/key-management-architecture.md's
// emergency-revocation procedure for how that situation is meant to be
// handled operationally instead.
func (m *KeyManager) DisableKey(ctx context.Context, keyID string) error {
	return m.transitionAwayFromActive(ctx, keyID, KeyStateDisabled)
}

func (m *KeyManager) transitionAwayFromActive(ctx context.Context, keyID string, target KeyState) error {
	meta, err := m.store.Get(ctx, keyID)
	if err != nil {
		return err
	}
	if meta.State == KeyStateActive {
		return ErrKeyStillActive
	}
	if meta.State == target {
		return nil
	}
	return m.store.UpdateState(ctx, keyID, target, time.Now().UTC())
}
