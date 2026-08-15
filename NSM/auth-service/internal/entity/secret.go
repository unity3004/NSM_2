package entity

import "time"

// Secret is the stable logical identity for a path — never overwritten in
// place; see SecretVersion for the append-only encrypted history attached
// to it. The same "stable parent identity + append-only child history"
// split this schema already uses for users/login_history and
// roles/audit_logs.
type Secret struct {
	ID             string
	OrganizationID string
	Path           string
	// CurrentVersion is denormalized from secret_versions for O(1) reads
	// on the hot "get the current value" path — kept in sync by
	// repository.SecretRepository.CreateVersion, which advances it in the
	// same transaction as the version insert it belongs to. Zero means no
	// version has ever been created yet.
	CurrentVersion int
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}

// IsDeleted reports whether this secret is currently soft-deleted — kept
// as a method here for the same reason entity.User.IsLocked is a method
// on User rather than duplicated at every call site: "deleted" has
// exactly one definition anywhere in this codebase.
func (s *Secret) IsDeleted() bool {
	return s.DeletedAt != nil
}

// SecretVersion is one immutable, encrypted version of a Secret. Every
// field describing the encrypted payload — Ciphertext, Nonce, AuthTag,
// Algorithm, WrappedDEK, KeyID, KeyVersion — is opaque to this entity and
// to everything below internal/secrets (a later phase not yet built):
// nothing at this layer can produce or interpret them, only persist and
// retrieve them byte-for-byte unchanged. There is deliberately no Update
// method anywhere in repository.SecretRepository for this type — a
// version, once created, is never modified; a logical "update" to a
// secret's value is always a new row with the next version number.
type SecretVersion struct {
	ID         string
	SecretID   string
	Version    int
	Ciphertext []byte
	Nonce      []byte
	AuthTag    []byte
	Algorithm  string
	WrappedDEK []byte
	KeyID      string
	KeyVersion *string
	CreatedBy  string
	CreatedAt  time.Time
	DeletedAt  *time.Time
}

// IsDeleted reports whether this specific version is soft-deleted —
// independent of whether the parent Secret itself is (see
// migrations/000024's own doc comment on the two separate deletion
// levels this schema supports).
func (v *SecretVersion) IsDeleted() bool {
	return v.DeletedAt != nil
}
