package service

import (
	"context"
	"crypto/rand"
	"errors"
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

func (p *fakeRotationProvider) GetCurrentKey(_ context.Context) ([]byte, string, error) {
	return p.keys[p.current], p.current, nil
}

func (p *fakeRotationProvider) GetKey(_ context.Context, keyID string) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, secrets.ErrKeyNotFound
	}
	return key, nil
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
	svc := NewKeyRotationService(km, secretRepo, auditTx)
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
