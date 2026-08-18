package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// SecretRepository persists entity.Secret (the stable logical identity for
// a path) and entity.SecretVersion (its append-only encrypted history).
// There is deliberately no UpdateVersion / method that mutates an existing
// secret_versions row anywhere on this interface — the only way to change
// a secret's value is CreateVersion, which always adds a new row. That
// asymmetry is the immutability guarantee: it holds because the interface
// makes the alternative impossible to call, not because callers remember
// not to.
type SecretRepository interface {
	// Create inserts a bare secret record — current_version 0, no versions
	// yet. If s.ID is already set (a caller that needs the ID before the
	// row exists — see CreateWithFirstVersion's own doc comment for why
	// Sprint 3 Phase 3's SecretService needs exactly that), it is used
	// verbatim instead of letting the database generate one.
	Create(ctx context.Context, s *entity.Secret) error
	GetByID(ctx context.Context, id string) (*entity.Secret, error)
	GetByPath(ctx context.Context, organizationID, path string) (*entity.Secret, error)
	List(ctx context.Context, organizationID string, f SecretFilter) ([]*entity.Secret, error)
	SoftDelete(ctx context.Context, id string) error

	// CreateWithFirstVersion atomically creates a new secret and its
	// version 1 in one transaction: the secret row never exists without a
	// version if this returns success, and neither exists at all if it
	// returns an error. This is what a caller that must guarantee "no
	// incomplete secret ever exists" (SecretService.CreateSecret) uses
	// instead of calling Create then CreateVersion as two independent
	// top-level calls — those two, taken separately, cannot give that
	// guarantee: a failure between them would leave an orphaned secret row
	// with zero versions. v.Version is fixed to 1 (ignoring any value the
	// caller set); v.SecretID is set to s.ID. On return, s.ID (if not
	// already set), s.CurrentVersion, s.CreatedAt, s.UpdatedAt, v.ID, and
	// v.CreatedAt are all populated.
	CreateWithFirstVersion(ctx context.Context, s *entity.Secret, v *entity.SecretVersion) error

	// CreateVersion assigns and inserts the next version number for
	// v.SecretID (ignoring any Version the caller set) and advances the
	// parent secret's CurrentVersion to match, atomically — see
	// postgres.secretRepository.CreateVersion for how. On return, v.ID,
	// v.Version and v.CreatedAt are populated. Equivalent to
	// CreateVersionIfCurrent with expectedCurrentVersion 0 (no check).
	CreateVersion(ctx context.Context, v *entity.SecretVersion) error
	// CreateVersionIfCurrent behaves exactly like CreateVersion, but
	// additionally enforces optimistic concurrency: inside the same row
	// lock CreateVersion already takes, it checks the secret's
	// CurrentVersion against expectedCurrentVersion before inserting — if
	// they no longer match (another writer's update landed first), it
	// rolls back and returns entity.ErrVersionConflict instead of
	// proceeding. expectedCurrentVersion <= 0 means "no expectation",
	// behaving exactly like CreateVersion.
	CreateVersionIfCurrent(ctx context.Context, v *entity.SecretVersion, expectedCurrentVersion int) error
	GetVersion(ctx context.Context, secretID string, version int) (*entity.SecretVersion, error)
	GetCurrentVersion(ctx context.Context, secretID string) (*entity.SecretVersion, error)
	ListVersions(ctx context.Context, secretID string) ([]*entity.SecretVersion, error)
	SoftDeleteVersion(ctx context.Context, secretID string, version int) error

	// CountVersionsByKeyID counts secret_versions rows across every
	// secret and organization whose key_id equals keyID — global, not
	// scoped to one secret, because internal/secrets.KeyManager's key
	// identifiers are themselves platform-wide (see
	// migrations/000026_create_encryption_keys_table's own doc comment on
	// why encryption_keys has no organization_id). This is
	// service.KeyRotationService.RetireKey's answer to "does any
	// remaining encrypted data require this key" — the reference check
	// the objective's ROTATION SAFETY section requires before a key may
	// move to KeyStateRetired. Soft-deleted versions still count: their
	// ciphertext is still present in the database and still needs this
	// key to ever be readable again, even though SecretService's normal
	// reads skip them.
	CountVersionsByKeyID(ctx context.Context, keyID string) (int, error)

	// ListVersionsByKeyID returns up to limit secret_versions rows —
	// across every secret and organization, the same platform-wide scope
	// CountVersionsByKeyID already uses and for the identical reason —
	// still encrypted under keyID. Soft-deleted versions are included,
	// same as CountVersionsByKeyID. Used by
	// service.ReEncryptionService to find bounded batches of work: each
	// call naturally returns the "next" unprocessed batch with no cursor
	// of its own needed, because ReEncryptVersion moves a row's key_id
	// away from keyID the moment it succeeds — an identical repeated
	// call to this method simply stops seeing a row once it has been
	// migrated, which is also what makes an interrupted migration safe
	// to resume with no separate progress bookkeeping (see that
	// service's own doc comment). limit <= 0 means a sane default, not
	// "unbounded" — this method never returns more than a bounded page
	// in one call.
	ListVersionsByKeyID(ctx context.Context, keyID string, limit int) ([]*entity.SecretVersion, error)

	// ReEncryptVersion atomically replaces versionID's encryption
	// envelope — ciphertext, nonce, auth_tag, wrapped_dek, key_id,
	// algorithm — and nothing else. This is the one deliberate, narrow
	// exception to this interface's own "versions are immutable" rule
	// (see this interface's package doc comment above): a version's
	// logical VALUE — what it decrypts to — is unchanged by construction
	// (the caller, service.ReEncryptionService, only ever writes back
	// what it just decrypted from the same row and immediately
	// re-encrypted; it never receives or accepts different plaintext),
	// only its storage representation changes. This method's own
	// signature makes it structurally impossible to use for anything
	// else — v carries only the six envelope fields, never Version,
	// SecretID, CreatedBy, CreatedAt, or DeletedAt.
	//
	// expectedKeyID is an optimistic-concurrency, compare-and-swap guard:
	// the update only applies if the row's key_id still equals
	// expectedKeyID at write time. If the row was already re-encrypted —
	// by an earlier run, or a concurrent run of the same migration —
	// since the caller last read it, expectedKeyID no longer matches,
	// this is a no-op (reencrypted is false), never an error and never a
	// corrupted write. This is the same mechanism that makes running a
	// migration twice safe (the second run's every candidate row already
	// fails this check, because ListVersionsByKeyID no longer returns
	// them in the first place).
	ReEncryptVersion(ctx context.Context, versionID string, v ReEncryptedEnvelope, expectedKeyID string) (reencrypted bool, err error)
}

// ReEncryptedEnvelope is the new encryption envelope
// SecretRepository.ReEncryptVersion writes for one row — field-for-field
// the same six columns entity.SecretVersion already carries, deliberately
// its own small type (not a full *entity.SecretVersion, and not
// secrets.EncryptedPayload — this package does not import
// internal/secrets; see entity.SecretVersion's own doc comment on why
// this layer stays independent of it) so ReEncryptVersion's signature
// cannot be mistaken for a general-purpose version update.
type ReEncryptedEnvelope struct {
	Ciphertext []byte
	Nonce      []byte
	AuthTag    []byte
	WrappedDEK []byte
	KeyID      string
	Algorithm  string
}

// SecretFilter narrows SecretRepository.List. Zero value means "no filter".
type SecretFilter struct {
	Cursor *string
	Limit  int
}
