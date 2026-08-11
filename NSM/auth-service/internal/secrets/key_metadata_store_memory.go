package secrets

import (
	"context"
	"sort"
	"sync"
	"time"
)

// InMemoryKeyMetadataStore is a KeyMetadataStore backed by a process-local
// map — no external dependency, usable in unit tests without a database.
//
// It is NOT durable: a process restart loses all rotation history and
// falls back to KeyManager's bootstrap path, which re-registers whatever
// the KeyProvider currently reports as ACTIVE. For a single, never-rotated
// key that reconstructs the same state; for a deployment that has actually
// rotated, restarting with this store loses the record of retired/disabled
// keys' lifecycle timestamps (their *decryptability* is unaffected — that
// depends only on the KeyProvider still holding the key material and
// EncryptionService's own stored key_id, neither of which this store
// touches — but their KeyState bookkeeping resets to "unknown until next
// bootstrap decides otherwise"). Do not use this in any deployment that
// performs real rotation; use a Postgres-backed KeyMetadataStore
// (internal/repository/postgres) instead. See
// NSM/key-management-architecture.md.
type InMemoryKeyMetadataStore struct {
	mu   sync.Mutex
	keys map[string]KeyMetadata
}

// NewInMemoryKeyMetadataStore constructs an empty store.
func NewInMemoryKeyMetadataStore() *InMemoryKeyMetadataStore {
	return &InMemoryKeyMetadataStore{keys: make(map[string]KeyMetadata)}
}

func (s *InMemoryKeyMetadataStore) Get(_ context.Context, keyID string) (KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta, ok := s.keys[keyID]
	if !ok {
		return KeyMetadata{}, ErrKeyNotFound
	}
	return meta, nil
}

func (s *InMemoryKeyMetadataStore) GetActive(_ context.Context) (KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, meta := range s.keys {
		if meta.State == KeyStateActive {
			return meta, nil
		}
	}
	return KeyMetadata{}, ErrNoActiveKey
}

func (s *InMemoryKeyMetadataStore) List(_ context.Context) ([]KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]KeyMetadata, 0, len(s.keys))
	for _, meta := range s.keys {
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *InMemoryKeyMetadataStore) Bootstrap(_ context.Context, meta KeyMetadata) (KeyMetadata, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) > 0 {
		if existing, ok := s.keys[meta.KeyID]; ok {
			return existing, false, nil
		}
	}
	s.keys[meta.KeyID] = meta
	return meta, true, nil
}

func (s *InMemoryKeyMetadataStore) ActivateNewKey(_ context.Context, newKeyID, algorithm string, now time.Time) (KeyMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[newKeyID]; exists {
		return KeyMetadata{}, ErrKeyAlreadyExists
	}
	for id, meta := range s.keys {
		if meta.State == KeyStateActive {
			meta.State = KeyStateRetiring
			s.keys[id] = meta
		}
	}
	meta := KeyMetadata{
		KeyID:       newKeyID,
		Algorithm:   algorithm,
		State:       KeyStateActive,
		CreatedAt:   now,
		ActivatedAt: &now,
	}
	s.keys[newKeyID] = meta
	return meta, nil
}

func (s *InMemoryKeyMetadataStore) UpdateState(_ context.Context, keyID string, newState KeyState, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta, ok := s.keys[keyID]
	if !ok {
		return ErrKeyNotFound
	}
	meta.State = newState
	switch newState {
	case KeyStateActive:
		meta.ActivatedAt = &at
	case KeyStateRetired:
		meta.RetiredAt = &at
	case KeyStateDisabled:
		meta.DisabledAt = &at
	}
	s.keys[keyID] = meta
	return nil
}
