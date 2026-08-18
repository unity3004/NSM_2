package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/secrets"
)

// fakeRotationProvider is a minimal multi-key secrets.KeyProvider test
// double — DevKeyProvider is deliberately single-key-only (see its own doc
// comment), so KeyRotationService's tests, like internal/secrets'
// key_manager_test.go, need something that can actually hold more than
// one key to rotate between.
type fakeRotationProvider struct {
	current string
	keys    map[string][]byte
}

func newFakeRotationProvider(t *testing.T, currentID string) *fakeRotationProvider {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return &fakeRotationProvider{current: currentID, keys: map[string][]byte{currentID: key}}
}

func (p *fakeRotationProvider) addKey(t *testing.T, keyID string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	p.keys[keyID] = key
}

func (p *fakeRotationProvider) GetCurrentKey(ctx context.Context) ([]byte, string, error) {
	key, err := p.GetKey(ctx, p.current)
	return key, p.current, err
}

// GetKey returns a defensive copy — see test/integration/key_rotation_test.go's
// multiKeyTestProvider.GetKey for why an aliased slice here would be a
// latent bug (EncryptionService zeroes whatever a KeyProvider returns).
// This test double doesn't exercise Encrypt/Decrypt today, but copying
// here keeps it safe if a future test does.
func (p *fakeRotationProvider) GetKey(_ context.Context, keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, secrets.ErrKeyNotFound
	}
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

// GenerateKey implements secrets.KeyGenerator — the same "key-vN,
// smallest unused N" convention DevKeyProvider.GenerateKey uses in the
// real implementation, so RotateToNewKey's tests exercise realistic
// sequential IDs rather than an arbitrary test-only naming scheme.
func (p *fakeRotationProvider) GenerateKey(_ context.Context) (string, error) {
	max := 0
	for id := range p.keys {
		var n int
		if _, err := fmt.Sscanf(id, "key-v%d", &n); err == nil && n > max {
			max = n
		}
	}
	newID := fmt.Sprintf("key-v%d", max+1)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	p.keys[newID] = key
	return newID, nil
}

// testKeyRotationEnv mirrors testSecretEnv's shape for KeyRotationService.
type testKeyRotationEnv struct {
	svc        *KeyRotationService
	secretRepo *mocks.FakeSecretRepository
	audit      *mocks.FakeAuditLogRepository
	provider   *fakeRotationProvider
}

func newTestKeyRotationEnv(t *testing.T) *testKeyRotationEnv {
	t.Helper()
	provider := newFakeRotationProvider(t, "key-v1")
	km := secrets.NewKeyManager(provider, secrets.NewInMemoryKeyMetadataStore())
	secretRepo := mocks.NewFakeSecretRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)
	svc := NewKeyRotationService(km, secretRepo, auditTx, provider)
	return &testKeyRotationEnv{svc: svc, secretRepo: secretRepo, audit: audit, provider: provider}
}

// newTestKeyRotationEnvNoGenerator mirrors newTestKeyRotationEnv but
// constructs the service with a nil KeyGenerator — the shape a real
// KMS-backed deployment would have (see NewKeyRotationService's own doc
// comment) — for tests asserting RotateToNewKey's ErrKeyGenerationUnsupported
// behavior specifically.
func newTestKeyRotationEnvNoGenerator(t *testing.T) *testKeyRotationEnv {
	t.Helper()
	provider := newFakeRotationProvider(t, "key-v1")
	km := secrets.NewKeyManager(provider, secrets.NewInMemoryKeyMetadataStore())
	secretRepo := mocks.NewFakeSecretRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)
	svc := NewKeyRotationService(km, secretRepo, auditTx, nil)
	return &testKeyRotationEnv{svc: svc, secretRepo: secretRepo, audit: audit, provider: provider}
}

func TestKeyRotationService_EnsureBootstrapped(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()

	meta, err := env.svc.EnsureBootstrapped(ctx)
	if err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}
	if meta.KeyID != "key-v1" || meta.State != secrets.KeyStateActive {
		t.Fatalf("EnsureBootstrapped() = %+v, want KeyID=key-v1 State=active", meta)
	}

	var actions []string
	for _, e := range env.audit.Entries {
		actions = append(actions, e.Action)
	}
	wantActions := map[string]bool{"key.created": false, "key.activated": false}
	for _, a := range actions {
		if _, ok := wantActions[a]; ok {
			wantActions[a] = true
		}
	}
	for action, seen := range wantActions {
		if !seen {
			t.Errorf("EnsureBootstrapped() did not record a %q audit event; got actions %v", action, actions)
		}
	}
	for _, e := range env.audit.Entries {
		if e.ActorType != entity.AuditActorSystem {
			t.Errorf("bootstrap audit entry ActorType = %q, want system", e.ActorType)
		}
		if e.OrganizationID != nil {
			t.Errorf("bootstrap audit entry OrganizationID = %v, want nil (key management is platform-wide)", *e.OrganizationID)
		}
	}

	// Idempotent: a second call must not write any more audit events.
	countBefore := len(env.audit.Entries)
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("second EnsureBootstrapped() error = %v", err)
	}
	if len(env.audit.Entries) != countBefore {
		t.Errorf("second EnsureBootstrapped() wrote %d more audit entries, want 0 (already bootstrapped)", len(env.audit.Entries)-countBefore)
	}
}

func TestKeyRotationService_RotateKey(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	env.provider.addKey(t, "key-v2")

	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	meta, err := env.svc.RotateKey(ctx, "admin-1", "key-v2", "203.0.113.5")
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if meta.KeyID != "key-v2" || meta.State != secrets.KeyStateActive {
		t.Fatalf("RotateKey() = %+v, want KeyID=key-v2 State=active", meta)
	}

	current, err := env.svc.CurrentKey(ctx)
	if err != nil || current.KeyID != "key-v2" {
		t.Errorf("CurrentKey() after rotation = %+v (err %v), want key-v2", current, err)
	}

	foundStarted, foundCompleted, foundActivated := false, false, false
	for _, e := range env.audit.Entries {
		if e.ResourceID == nil || *e.ResourceID != "key-v2" {
			continue
		}
		switch e.Action {
		case "key.rotation_started":
			foundStarted = true
		case "key.rotation_completed":
			foundCompleted = true
		case "key.activated":
			foundActivated = true
		}
		if e.ActorType != entity.AuditActorUser || e.ActorID == nil || *e.ActorID != "admin-1" {
			t.Errorf("rotation audit entry %q ActorType/ActorID = %v/%v, want user/admin-1", e.Action, e.ActorType, e.ActorID)
		}
	}
	if !foundStarted || !foundCompleted || !foundActivated {
		t.Errorf("RotateKey() audit trail missing events: started=%v completed=%v activated=%v", foundStarted, foundCompleted, foundActivated)
	}
}

func TestKeyRotationService_RotateKey_RequiresActor(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	env.provider.addKey(t, "key-v2")
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	_, err := env.svc.RotateKey(ctx, "", "key-v2", "203.0.113.5")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("RotateKey() with no actor, error = %v, want entity.ErrForbidden", err)
	}
}

func TestKeyRotationService_RotateKey_UnavailableKey_RecordsFailureAudit(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	// key-v2 was never added to the provider.
	if _, err := env.svc.RotateKey(ctx, "admin-1", "key-v2", "203.0.113.5"); err == nil {
		t.Fatal("RotateKey() to an unavailable key, error = nil, want an error")
	}

	sawFailure := false
	for _, e := range env.audit.Entries {
		if e.Action == "key.rotation_started" && e.Result == entity.AuditResultFailure {
			sawFailure = true
			if e.Metadata != nil {
				if reason, _ := e.Metadata["error"].(string); strings.Contains(reason, "-----") {
					t.Errorf("failure audit metadata looks like it might contain key material: %v", e.Metadata)
				}
			}
		}
		if e.Action == "key.rotation_completed" {
			t.Error("a failed rotation must not record key.rotation_completed")
		}
	}
	if !sawFailure {
		t.Error("RotateKey() failure did not record a key.rotation_started/failure audit entry")
	}
}

// --- RotateToNewKey: the single-call rotation engine ---

func TestKeyRotationService_RotateToNewKey_Succeeds(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	meta, err := env.svc.RotateToNewKey(ctx, "admin-1", "203.0.113.5")
	if err != nil {
		t.Fatalf("RotateToNewKey() error = %v, want nil", err)
	}
	if meta.KeyID == "key-v1" {
		t.Fatal("RotateToNewKey() activated the pre-existing key instead of a genuinely new one")
	}
	if meta.State != secrets.KeyStateActive {
		t.Errorf("RotateToNewKey() new key state = %q, want active", meta.State)
	}

	current, err := env.svc.CurrentKey(ctx)
	if err != nil || current.KeyID != meta.KeyID {
		t.Errorf("CurrentKey() after RotateToNewKey() = %+v (err %v), want %q", current, err, meta.KeyID)
	}

	// CURRENT KEY -> ... -> OLD KEY = PREVIOUS: key-v1 must have moved to
	// RETIRING, not vanished.
	old, err := env.keyManagerMetadata(ctx, "key-v1")
	if err != nil {
		t.Fatalf("looking up key-v1 metadata after RotateToNewKey(), error = %v", err)
	}
	if old.State != secrets.KeyStateRetiring {
		t.Errorf("key-v1 state after RotateToNewKey() = %q, want retiring", old.State)
	}
}

// The full audit narrative RotateToNewKey should leave behind: the new
// key didn't exist before this call (key.created), then went through the
// same activation sequence RotateKey already writes.
func TestKeyRotationService_RotateToNewKey_RecordsFullAuditTrail(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	meta, err := env.svc.RotateToNewKey(ctx, "admin-1", "203.0.113.5")
	if err != nil {
		t.Fatalf("RotateToNewKey() error = %v", err)
	}

	seen := map[string]bool{}
	for _, e := range env.audit.Entries {
		if e.ResourceID == nil || *e.ResourceID != meta.KeyID {
			continue
		}
		seen[e.Action] = true
		if e.ActorType != entity.AuditActorUser || e.ActorID == nil || *e.ActorID != "admin-1" {
			t.Errorf("%q audit entry ActorType/ActorID = %v/%v, want user/admin-1", e.Action, e.ActorType, e.ActorID)
		}
	}
	for _, action := range []string{"key.created", "key.rotation_started", "key.rotation_completed", "key.activated"} {
		if !seen[action] {
			t.Errorf("RotateToNewKey() audit trail missing %q for the new key", action)
		}
	}
}

func TestKeyRotationService_RotateToNewKey_RequiresActor(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	_, err := env.svc.RotateToNewKey(ctx, "", "203.0.113.5")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("RotateToNewKey() with no actor, error = %v, want entity.ErrForbidden", err)
	}
}

// A missing actor must be rejected before a key is even generated — an
// unauthorized call must never consume a key-vN identifier.
func TestKeyRotationService_RotateToNewKey_RequiresActor_NeverGeneratesKey(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}
	before := len(env.provider.keys)

	if _, err := env.svc.RotateToNewKey(ctx, "", "203.0.113.5"); !errors.Is(err, entity.ErrForbidden) {
		t.Fatalf("RotateToNewKey() with no actor, error = %v, want entity.ErrForbidden", err)
	}
	if len(env.provider.keys) != before {
		t.Errorf("RotateToNewKey() with no actor still registered a new key with the provider (%d keys, want %d)", len(env.provider.keys), before)
	}
}

func TestKeyRotationService_RotateToNewKey_NoGeneratorConfigured_Fails(t *testing.T) {
	env := newTestKeyRotationEnvNoGenerator(t)
	ctx := t.Context()
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	_, err := env.svc.RotateToNewKey(ctx, "admin-1", "203.0.113.5")
	if !errors.Is(err, ErrKeyGenerationUnsupported) {
		t.Errorf("RotateToNewKey() with no KeyGenerator configured, error = %v, want ErrKeyGenerationUnsupported", err)
	}

	// Unaffected: the pre-existing active key must remain active.
	current, err := env.svc.CurrentKey(ctx)
	if err != nil || current.KeyID != "key-v1" {
		t.Errorf("CurrentKey() after a refused RotateToNewKey(), error = %v, meta = %+v, want key-v1 still active", err, current)
	}
}

// Repeated calls must each mint a distinct, sequential key — proving the
// engine can be used for genuine multi-generation rotation, not just a
// single one-shot key-v1 -> key-v2 transition.
func TestKeyRotationService_RotateToNewKey_SequentialAcrossMultipleCalls(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}

	first, err := env.svc.RotateToNewKey(ctx, "admin-1", "")
	if err != nil {
		t.Fatalf("first RotateToNewKey() error = %v", err)
	}
	second, err := env.svc.RotateToNewKey(ctx, "admin-1", "")
	if err != nil {
		t.Fatalf("second RotateToNewKey() error = %v", err)
	}
	if first.KeyID == second.KeyID {
		t.Fatalf("two RotateToNewKey() calls produced the same key ID %q", first.KeyID)
	}

	all, err := env.svc.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(all) != 3 { // key-v1 (bootstrap) + two generated keys
		t.Fatalf("ListKeys() returned %d keys, want 3 (rotation must never remove a key)", len(all))
	}
}

// keyManagerMetadata is a small test helper — KeyRotationService exposes
// CurrentKey/ListKeys but not an arbitrary-key-by-ID lookup, so this
// reaches ListKeys and filters, exactly what an operator inspecting
// rotation results would do with the same public surface.
func (env *testKeyRotationEnv) keyManagerMetadata(ctx context.Context, keyID string) (secrets.KeyMetadata, error) {
	all, err := env.svc.ListKeys(ctx)
	if err != nil {
		return secrets.KeyMetadata{}, err
	}
	for _, m := range all {
		if m.KeyID == keyID {
			return m, nil
		}
	}
	return secrets.KeyMetadata{}, secrets.ErrKeyNotFound
}

// --- RetireKey: the ROTATION SAFETY reference check ---

func TestKeyRotationService_RetireKey_RefusesWhenStillReferenced(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	env.provider.addKey(t, "key-v2")
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}
	if _, err := env.svc.RotateKey(ctx, "admin-1", "key-v2", ""); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	// Seed a secret version that still references key-v1.
	env.secretRepo.SeedVersion(&entity.SecretVersion{SecretID: "s1", Version: 1, KeyID: "key-v1"})

	err := env.svc.RetireKey(ctx, "admin-1", "key-v1", "")
	if err == nil {
		t.Fatal("RetireKey() of a still-referenced key, error = nil, want an error")
	}
}

func TestKeyRotationService_RetireKey_SucceedsWhenUnreferenced(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	env.provider.addKey(t, "key-v2")
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}
	if _, err := env.svc.RotateKey(ctx, "admin-1", "key-v2", ""); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	if err := env.svc.RetireKey(ctx, "admin-1", "key-v1", "203.0.113.5"); err != nil {
		t.Fatalf("RetireKey() of an unreferenced key, error = %v, want nil", err)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "key.retired" && e.ResourceID != nil && *e.ResourceID == "key-v1" && e.Result == entity.AuditResultSuccess {
			found = true
		}
	}
	if !found {
		t.Error("RetireKey() success did not record a key.retired audit entry")
	}
}

func TestKeyRotationService_DisableKey_RecordsReasonNeverKeyMaterial(t *testing.T) {
	env := newTestKeyRotationEnv(t)
	ctx := t.Context()
	env.provider.addKey(t, "key-v2")
	rawKeyV1 := append([]byte(nil), env.provider.keys["key-v1"]...)
	if _, err := env.svc.EnsureBootstrapped(ctx); err != nil {
		t.Fatalf("EnsureBootstrapped() error = %v", err)
	}
	if _, err := env.svc.RotateKey(ctx, "admin-1", "key-v2", ""); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	if err := env.svc.DisableKey(ctx, "admin-1", "key-v1", "suspected compromise", "203.0.113.5"); err != nil {
		t.Fatalf("DisableKey() error = %v", err)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action != "key.disabled" {
			continue
		}
		found = true
		reason, _ := e.Metadata["reason"].(string)
		if reason != "suspected compromise" {
			t.Errorf("key.disabled metadata reason = %q, want %q", reason, "suspected compromise")
		}
	}
	if !found {
		t.Error("DisableKey() did not record a key.disabled audit entry")
	}

	// 11/12. No audit entry anywhere contains raw key material.
	needle := string(rawKeyV1)
	for _, e := range env.audit.Entries {
		for k, v := range e.Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, needle) {
				t.Errorf("audit entry %q metadata field %q contains raw key material", e.Action, k)
			}
		}
	}
}
