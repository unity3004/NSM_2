package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/policy"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/secrets"
	"github.com/acme/auth-service/internal/util"
)

// Permission strings SecretService checks — migrations/000022 seeds
// create/read/update/delete, migrations/000025 seeds list. Compile-time
// constants, never assembled from request data, the same discipline every
// requirePermission("...", ...) call site in router.go already follows.
const (
	permSecretsCreate = "secrets:create"
	permSecretsRead   = "secrets:read"
	permSecretsUpdate = "secrets:update"
	permSecretsDelete = "secrets:delete"
	permSecretsList   = "secrets:list"
	// permSecretsRollback (migrations/000032) is deliberately its own
	// capability, not an alias for permSecretsUpdate — "read a secret's
	// history" (permSecretsRead, ListVersions below) must not imply "may
	// make an old value current again." See RollbackSecret's own doc
	// comment.
	permSecretsRollback = "secrets:rollback"
)

// ErrEmptyPayload means Create/UpdateSecret was called with no key/value
// data at all — never a wire-format or validation-envelope error type
// (see util.ErrInvalidSecretPath's own doc comment on why: no DTO layer
// exists yet to own that translation).
var ErrEmptyPayload = errors.New("service: secret payload must not be empty")

// SecretService is Sprint 3 Phase 3's business-logic layer for the
// Secrets Engine — the one place authenticated identity, RBAC
// authorization, path validation, AES-256-GCM envelope encryption
// (internal/secrets, Phase 2), persistence (repository.SecretRepository,
// Phase 1), and audit logging are coordinated for every secret operation.
// It creates no cryptography, no RBAC logic, and no audit mechanism of
// its own — every one of those is an existing, unmodified dependency.
//
// Authorization happens INSIDE this service, not only in HTTP
// middleware — a deliberate divergence from UserService and every other
// service in this codebase. Elsewhere, middleware.RequirePermission
// rejects an unauthorized request before a service method ever runs, and
// the service trusts that already happened (see that middleware's own
// doc comment). SecretService cannot make that assumption: this phase
// builds no REST handlers or router wiring for it at all (see this
// sprint's own explicit scope), so there is no middleware layer in front
// of it yet to do that job. Every write and read method below performs
// its own real-time RBACService.HasPermission check against the
// caller-supplied ActorUserID instead — the exact same check
// middleware.RequirePermission performs, just made from inside the
// service rather than in front of it. When a future phase adds REST
// handlers for secrets, this becomes defense-in-depth alongside that
// middleware, not a replacement for it — neither layer should be removed
// in favor of the other.
//
// The one thing SecretService never does is verify a bearer token or
// resolve a session itself — "authenticate" in this type's flows means
// "trust the ActorUserID the caller supplies came from a real,
// already-completed login," the same trust boundary every existing
// service in this codebase (UserService.AssignRole, and so on) already
// operates on. An ActorUserID of "" is treated as no authenticated
// identity at all and rejected outright, before RBAC is even consulted.
type SecretService struct {
	repo     repository.SecretRepository
	enc      *secrets.EncryptionService
	rbac     *RBACService
	policies *SecretPolicyService
	auditTx  AuditTxFunc
}

// NewSecretService constructs a SecretService. policies is required, not
// optional like auditTx (nil would defeat Sprint 4 Task 2's deny-by-default
// requirement outright — every method below calls
// authorizeSecretAccess, which always consults it) — see that method's
// own doc comment for the full "global permission, then path policy"
// authorization flow this adds on top of the RBAC check that already
// existed.
func NewSecretService(repo repository.SecretRepository, enc *secrets.EncryptionService, rbac *RBACService, policies *SecretPolicyService, auditTx AuditTxFunc) *SecretService {
	return &SecretService{repo: repo, enc: enc, rbac: rbac, policies: policies, auditTx: auditTx}
}

// SecretMetadata is what every method below returns about a secret except
// its value — safe to log, safe to return to any authorized caller
// regardless of whether they also hold secrets:read. Never contains
// ciphertext, a nonce, a key ID, or any other encryption-shaped field.
type SecretMetadata struct {
	ID             string
	Path           string
	CurrentVersion int
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func secretMetadataFromEntity(s *entity.Secret) SecretMetadata {
	return SecretMetadata{
		ID: s.ID, Path: s.Path, CurrentVersion: s.CurrentVersion,
		CreatedBy: s.CreatedBy, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

// CreateSecretInput is CreateSecret's argument. Payload is the entire
// structured key/value secret (e.g. {"username": ..., "password": ...,
// "host": ..., "port": ...]) — the whole map is encrypted as one unit;
// there is no per-field selective encryption anywhere in this service.
type CreateSecretInput struct {
	OrganizationID string
	Path           string
	Payload        map[string]string
	ActorUserID    string
	// ActorIsServiceAccount (Sprint 5 Task 1) distinguishes a machine
	// caller from a human one — see authorize's own doc comment for why
	// this changes which RBAC table ActorUserID is checked against.
	// Zero-value false, so every pre-existing caller that never sets it
	// keeps its original, correct "this is a user" behavior unchanged.
	ActorIsServiceAccount bool
	IPAddress             string
}

// CreateSecret implements the flow: authorize, validate path, validate
// payload, check for an existing secret at this path, encrypt, create the
// secret and its version 1 atomically, record an audit event, return
// metadata only — never plaintext, never key material.
//
// "No incomplete secret should remain" if persistence fails is met by
// repository.SecretRepository.CreateWithFirstVersion, which creates the
// secret row and its first version in one database transaction — see that
// method's own doc comment for why Create+CreateVersion as two
// independent calls could not give this guarantee.
func (s *SecretService) CreateSecret(ctx context.Context, in CreateSecretInput) (SecretMetadata, error) {
	path, err := s.authorizeSecretAccess(ctx, in.ActorUserID, in.ActorIsServiceAccount, in.OrganizationID, permSecretsCreate, in.Path, in.IPAddress, policy.ActionCreate)
	if err != nil {
		return SecretMetadata{}, err
	}
	if len(in.Payload) == 0 {
		return SecretMetadata{}, ErrEmptyPayload
	}

	// Application-level pre-check: a fast, clear entity.ErrAlreadyExists
	// before spending an encryption operation on a request that's going to
	// fail anyway. The real, race-proof guarantee is
	// uq_secrets_org_path (migrations/000024), enforced inside
	// CreateWithFirstVersion's own INSERT below — two concurrent creates
	// for the same path can both pass this pre-check, but only one can
	// ever win the actual insert.
	if _, err := s.repo.GetByPath(ctx, in.OrganizationID, path); err == nil {
		return SecretMetadata{}, entity.ErrAlreadyExists
	} else if !errors.Is(err, entity.ErrNotFound) {
		return SecretMetadata{}, err
	}

	plaintext, err := json.Marshal(in.Payload)
	if err != nil {
		return SecretMetadata{}, fmt.Errorf("service: marshaling secret payload: %w", err)
	}

	// Generated here, before the row exists, so EncryptContext can bind
	// AES-GCM's additional authenticated data to the secret's own identity
	// during encryption (see secrets.EncryptContext's doc comment) —
	// repository.SecretRepository.Create/CreateWithFirstVersion both use
	// this ID verbatim instead of letting the database generate one.
	secretID := util.NewUUID()
	encrypted, err := s.enc.Encrypt(ctx, plaintext, secrets.EncryptContext{SecretID: secretID, Version: 1})
	if err != nil {
		return SecretMetadata{}, err
	}

	secret := &entity.Secret{ID: secretID, OrganizationID: in.OrganizationID, Path: path, CreatedBy: in.ActorUserID}
	version := &entity.SecretVersion{
		Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce, AuthTag: encrypted.AuthTag,
		Algorithm: encrypted.Algorithm, WrappedDEK: encrypted.WrappedDEK, KeyID: encrypted.KeyID,
		CreatedBy: in.ActorUserID,
	}
	if err := s.repo.CreateWithFirstVersion(ctx, secret, version); err != nil {
		return SecretMetadata{}, err
	}

	s.recordSecretAudit(ctx, "secret.created", in.ActorUserID, in.ActorIsServiceAccount, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path, "version": version.Version})
	return secretMetadataFromEntity(secret), nil
}

// GetSecretInput is GetSecret's argument. Version nil means "the current
// version"; a non-nil Version requests that specific historical version —
// see repository.SecretRepository.GetVersion/GetCurrentVersion, both of
// which this method delegates to unchanged.
type GetSecretInput struct {
	OrganizationID        string
	Path                  string
	Version               *int
	ActorUserID           string
	ActorIsServiceAccount bool
	IPAddress             string
}

// SecretValue is GetSecret's return value — the one place this service
// ever returns a decrypted payload. Never cached, never logged; the
// caller is responsible for not retaining Payload longer than the
// request that asked for it needs it (see internal/secrets' own package
// doc comment on the same discipline one layer down).
type SecretValue struct {
	Metadata SecretMetadata
	Version  int
	Payload  map[string]string
}

// GetSecret implements: authenticate (trust ActorUserID) -> authorize
// secrets:read -> validate path -> find secret -> determine requested
// version -> fetch the encrypted version -> decrypt -> audit -> return.
//
// Authorization happens before any database call and before any
// decryption — never the reverse. This is the one ordering requirement
// this method exists to enforce: an unauthorized caller is rejected by
// the RBAC check alone, before GetByPath/GetVersion ever runs, so a
// caller who lacks secrets:read learns nothing about whether a path
// exists, let alone its value.
func (s *SecretService) GetSecret(ctx context.Context, in GetSecretInput) (SecretValue, error) {
	path, err := s.authorizeSecretAccess(ctx, in.ActorUserID, in.ActorIsServiceAccount, in.OrganizationID, permSecretsRead, in.Path, in.IPAddress, policy.ActionRead)
	if err != nil {
		return SecretValue{}, err
	}

	secret, err := s.repo.GetByPath(ctx, in.OrganizationID, path)
	if err != nil {
		return SecretValue{}, err
	}

	var version *entity.SecretVersion
	if in.Version == nil {
		version, err = s.repo.GetCurrentVersion(ctx, secret.ID)
	} else {
		version, err = s.repo.GetVersion(ctx, secret.ID, *in.Version)
	}
	if err != nil {
		return SecretValue{}, err
	}

	encrypted := &secrets.EncryptedPayload{
		Ciphertext: version.Ciphertext, Nonce: version.Nonce, AuthTag: version.AuthTag,
		WrappedDEK: version.WrappedDEK, KeyID: version.KeyID, Algorithm: version.Algorithm,
	}
	plaintext, err := s.enc.Decrypt(ctx, encrypted, secrets.EncryptContext{SecretID: secret.ID, Version: version.Version})
	if err != nil {
		return SecretValue{}, err
	}

	var payload map[string]string
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return SecretValue{}, fmt.Errorf("service: unmarshaling decrypted secret payload: %w", err)
	}

	// A caller who named a specific version (in.Version != nil) explicitly
	// asked to look at history, not "the" value — distinct enough from an
	// ordinary current-version read to get its own audit action
	// (secret.version_accessed) rather than folding into secret.read,
	// which every current-version GetSecret call before this phase already
	// produced and keeps producing unchanged.
	action := "secret.read"
	if in.Version != nil {
		action = "secret.version_accessed"
	}
	s.recordSecretAudit(ctx, action, in.ActorUserID, in.ActorIsServiceAccount, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path, "version": version.Version})
	return SecretValue{Metadata: secretMetadataFromEntity(secret), Version: version.Version, Payload: payload}, nil
}

// SecretVersionMetadata is one row of ListVersions' result — deliberately
// as safe to return as SecretMetadata (no ciphertext, nonce, or key
// field), plus Current, which SecretMetadata itself has no reason to
// carry (it already describes exactly one version implicitly: whichever
// GetSecret/CreateSecret/UpdateSecret happened to fetch or create).
type SecretVersionMetadata struct {
	Version   int
	CreatedBy string
	CreatedAt time.Time
	Current   bool
}

// ListVersionsInput is ListVersions' argument.
type ListVersionsInput struct {
	OrganizationID        string
	Path                  string
	ActorUserID           string
	ActorIsServiceAccount bool
	IPAddress             string
}

// ListVersions returns metadata for every non-destroyed version of the
// secret at Path, newest first — never a payload, ciphertext, nonce, or
// key ID (see SecretVersionMetadata's own doc comment). Gated on
// secrets:read + the path's own read policy, the identical authorization
// GetSecret already requires: viewing what versions exist is a read of
// this secret, the same way viewing its current value is, and holding
// permission to read a value implies permission to see the version
// history that value is one entry of. This is deliberately not gated by
// secrets:list — that permission controls seeing which *paths* exist
// across the whole organization (SecretService.ListSecrets), a different
// capability from seeing one already-known path's own history.
func (s *SecretService) ListVersions(ctx context.Context, in ListVersionsInput) ([]SecretVersionMetadata, error) {
	path, err := s.authorizeSecretAccess(ctx, in.ActorUserID, in.ActorIsServiceAccount, in.OrganizationID, permSecretsRead, in.Path, in.IPAddress, policy.ActionRead)
	if err != nil {
		return nil, err
	}

	secret, err := s.repo.GetByPath(ctx, in.OrganizationID, path)
	if err != nil {
		return nil, err
	}
	versions, err := s.repo.ListVersions(ctx, secret.ID)
	if err != nil {
		return nil, err
	}

	out := make([]SecretVersionMetadata, 0, len(versions))
	for _, v := range versions {
		out = append(out, SecretVersionMetadata{
			Version: v.Version, CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt,
			Current: v.Version == secret.CurrentVersion,
		})
	}
	return out, nil
}

// UpdateSecretInput is UpdateSecret's argument. ExpectedVersion is
// required (must be positive) and must equal the secret's current
// version at the moment the update actually applies — see UpdateSecret's
// own doc comment for why this can never be optional.
type UpdateSecretInput struct {
	OrganizationID        string
	Path                  string
	ExpectedVersion       int
	Payload               map[string]string
	ActorUserID           string
	ActorIsServiceAccount bool
	IPAddress             string
}

// UpdateSecret creates a new immutable version — it never modifies an
// existing secret_versions row (repository.SecretRepository has no method
// that could). ExpectedVersion implements optimistic concurrency: if the
// secret's current version no longer matches it by the time the write
// actually reaches its row lock, entity.ErrVersionConflict is returned
// and nothing is written — never a silent overwrite of a change the
// caller didn't know about.
//
// ExpectedVersion is required, not optional, on purpose: an "update
// without stating what you expect" would defeat the entire point of this
// check, and this codebase's own instruction is explicit — "do not
// silently overwrite changes" — for every update, not just ones that opt
// in.
//
// The version number encryption binds into AES-GCM's additional
// authenticated data (ExpectedVersion+1) and the version number
// CreateVersionIfCurrent actually assigns inside its row lock are
// guaranteed to match whenever the concurrency check passes: if no
// concurrent writer intervened, the secret's current version at lock time
// is exactly what this method already read, so
// current+1 == ExpectedVersion+1. If a concurrent writer did intervene,
// the whole call fails before anything is persisted — there is no
// pathway to a stored row whose AAD version disagrees with its actual
// version column.
func (s *SecretService) UpdateSecret(ctx context.Context, in UpdateSecretInput) (SecretMetadata, error) {
	path, err := s.authorizeSecretAccess(ctx, in.ActorUserID, in.ActorIsServiceAccount, in.OrganizationID, permSecretsUpdate, in.Path, in.IPAddress, policy.ActionUpdate)
	if err != nil {
		return SecretMetadata{}, err
	}
	if in.ExpectedVersion <= 0 {
		return SecretMetadata{}, fmt.Errorf("service: UpdateSecret requires a positive ExpectedVersion")
	}
	if len(in.Payload) == 0 {
		return SecretMetadata{}, ErrEmptyPayload
	}

	secret, err := s.repo.GetByPath(ctx, in.OrganizationID, path)
	if err != nil {
		return SecretMetadata{}, err
	}
	if secret.CurrentVersion != in.ExpectedVersion {
		return SecretMetadata{}, entity.ErrVersionConflict
	}

	plaintext, err := json.Marshal(in.Payload)
	if err != nil {
		return SecretMetadata{}, fmt.Errorf("service: marshaling secret payload: %w", err)
	}

	nextVersion := in.ExpectedVersion + 1
	encrypted, err := s.enc.Encrypt(ctx, plaintext, secrets.EncryptContext{SecretID: secret.ID, Version: nextVersion})
	if err != nil {
		return SecretMetadata{}, err
	}

	version := &entity.SecretVersion{
		SecretID: secret.ID, Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce, AuthTag: encrypted.AuthTag,
		Algorithm: encrypted.Algorithm, WrappedDEK: encrypted.WrappedDEK, KeyID: encrypted.KeyID,
		CreatedBy: in.ActorUserID,
	}
	if err := s.repo.CreateVersionIfCurrent(ctx, version, in.ExpectedVersion); err != nil {
		return SecretMetadata{}, err
	}
	secret.CurrentVersion = version.Version
	secret.UpdatedAt = version.CreatedAt

	s.recordSecretAudit(ctx, "secret.updated", in.ActorUserID, in.ActorIsServiceAccount, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path, "version": version.Version})
	return secretMetadataFromEntity(secret), nil
}

// RollbackSecretInput is RollbackSecret's argument. TargetVersion is the
// historical version whose value becomes the new current one — never the
// version number the result is stored as (see RollbackSecret's own doc
// comment: that is always ExpectedVersion + 1, decided the same way
// UpdateSecret decides it, not supplied by the caller). ExpectedVersion is
// the version the caller believes is current right now — required, for
// the identical reason UpdateSecretInput.ExpectedVersion is required, not
// optional: see that field's own doc comment.
type RollbackSecretInput struct {
	OrganizationID        string
	Path                  string
	TargetVersion         int
	ExpectedVersion       int
	ActorUserID           string
	ActorIsServiceAccount bool
	IPAddress             string
}

// RollbackSecret creates a new version whose plaintext equals
// TargetVersion's — it never deletes, restores, or renumbers anything.
// Version 1 = A, 2 = B, 3 = C, rollback to 1 produces version 4 = A;
// versions 1, 2, and 3 all remain exactly as they were, byte for byte,
// forever retrievable through GetSecret/ListVersions like any other
// version. This is the one safe way this service ever "undoes" a change —
// there is deliberately no method anywhere in this codebase that deletes
// or overwrites a newer version to get back to an older value.
//
// Gated on secrets:rollback specifically, not secrets:update — see
// permSecretsRollback's own doc comment for why holding secrets:read (or
// even secrets:update) must not be enough on its own. The path-policy
// layer still checks policy.ActionUpdate, the same action an ordinary
// update requires: a rollback is, in every way that matters to the path
// policy, a write to this path.
//
// Concurrency and "don't silently overwrite a change you didn't know
// about" both work exactly like UpdateSecret: ExpectedVersion is checked
// against the secret's actual current version before anything is
// decrypted or encrypted, and CreateVersionIfCurrent's row lock
// re-validates that same expectation atomically before the insert
// happens. This matters specifically for rollback, not just symmetry with
// update: without it, a rollback silently re-anchors itself to whatever
// version happens to be current at the moment it runs rather than the
// version its caller actually looked at before clicking "roll back" — two
// racing writers (one rollback, one ordinary update) would then both
// succeed, one quietly on top of the other, instead of the second one
// failing with entity.ErrVersionConflict the way this codebase's own "no
// silent overwrites, ever" rule requires.
func (s *SecretService) RollbackSecret(ctx context.Context, in RollbackSecretInput) (SecretMetadata, error) {
	path, err := s.authorizeSecretAccess(ctx, in.ActorUserID, in.ActorIsServiceAccount, in.OrganizationID, permSecretsRollback, in.Path, in.IPAddress, policy.ActionUpdate)
	if err != nil {
		return SecretMetadata{}, err
	}
	if in.TargetVersion <= 0 {
		return SecretMetadata{}, fmt.Errorf("service: RollbackSecret requires a positive TargetVersion")
	}
	if in.ExpectedVersion <= 0 {
		return SecretMetadata{}, fmt.Errorf("service: RollbackSecret requires a positive ExpectedVersion")
	}

	secret, err := s.repo.GetByPath(ctx, in.OrganizationID, path)
	if err != nil {
		return SecretMetadata{}, err
	}
	if secret.CurrentVersion != in.ExpectedVersion {
		return SecretMetadata{}, entity.ErrVersionConflict
	}

	// GetVersion filters deleted_at IS NULL exactly like GetByPath does for
	// the parent secret — a version this codebase's own (not yet exposed)
	// SoftDeleteVersion retired is entity.ErrNotFound here, the same as one
	// that never existed. "Roll back to a retired version" is refused, not
	// silently resurrected.
	target, err := s.repo.GetVersion(ctx, secret.ID, in.TargetVersion)
	if err != nil {
		return SecretMetadata{}, err
	}

	targetEncrypted := &secrets.EncryptedPayload{
		Ciphertext: target.Ciphertext, Nonce: target.Nonce, AuthTag: target.AuthTag,
		WrappedDEK: target.WrappedDEK, KeyID: target.KeyID, Algorithm: target.Algorithm,
	}
	plaintext, err := s.enc.Decrypt(ctx, targetEncrypted, secrets.EncryptContext{SecretID: secret.ID, Version: target.Version})
	if err != nil {
		return SecretMetadata{}, err
	}

	// Re-encrypted as a genuinely new version, never the target's ciphertext
	// copied verbatim: AES-GCM's additional authenticated data binds the
	// version number it was encrypted under (secrets.EncryptContext), so
	// version 4's stored ciphertext must be sealed with Version: 4, not the
	// Version: 1 target.Ciphertext already carries — reusing the old bytes
	// directly would fail to decrypt the moment anything read it back as
	// version 4.
	nextVersion := in.ExpectedVersion + 1
	reEncrypted, err := s.enc.Encrypt(ctx, plaintext, secrets.EncryptContext{SecretID: secret.ID, Version: nextVersion})
	if err != nil {
		return SecretMetadata{}, err
	}

	newVersion := &entity.SecretVersion{
		SecretID: secret.ID, Ciphertext: reEncrypted.Ciphertext, Nonce: reEncrypted.Nonce, AuthTag: reEncrypted.AuthTag,
		Algorithm: reEncrypted.Algorithm, WrappedDEK: reEncrypted.WrappedDEK, KeyID: reEncrypted.KeyID,
		CreatedBy: in.ActorUserID,
	}
	if err := s.repo.CreateVersionIfCurrent(ctx, newVersion, in.ExpectedVersion); err != nil {
		return SecretMetadata{}, err
	}
	secret.CurrentVersion = newVersion.Version
	secret.UpdatedAt = newVersion.CreatedAt

	s.recordSecretAudit(ctx, "secret.version_rollback", in.ActorUserID, in.ActorIsServiceAccount, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path, "from_version": in.TargetVersion, "to_version": newVersion.Version})
	return secretMetadataFromEntity(secret), nil
}

// DeleteSecretInput is DeleteSecret's argument.
type DeleteSecretInput struct {
	OrganizationID        string
	Path                  string
	ActorUserID           string
	ActorIsServiceAccount bool
	IPAddress             string
}

// DeleteSecret soft-deletes the logical secret (repository.SecretRepository.SoftDelete)
// — its ciphertext and every version's ciphertext remain in storage,
// exactly as migrations/000024 designed. After this call, GetSecret for
// this path returns entity.ErrNotFound (GetByPath already filters
// deleted_at IS NULL) — "normal read" cannot see a deleted secret.
// Permanent destruction is not implemented in this phase.
func (s *SecretService) DeleteSecret(ctx context.Context, in DeleteSecretInput) error {
	path, err := s.authorizeSecretAccess(ctx, in.ActorUserID, in.ActorIsServiceAccount, in.OrganizationID, permSecretsDelete, in.Path, in.IPAddress, policy.ActionDelete)
	if err != nil {
		return err
	}

	secret, err := s.repo.GetByPath(ctx, in.OrganizationID, path)
	if err != nil {
		return err
	}
	if err := s.repo.SoftDelete(ctx, secret.ID); err != nil {
		return err
	}

	s.recordSecretAudit(ctx, "secret.deleted", in.ActorUserID, in.ActorIsServiceAccount, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path})
	return nil
}

// ListSecretsInput is ListSecrets' argument.
type ListSecretsInput struct {
	OrganizationID        string
	Filter                repository.SecretFilter
	ActorUserID           string
	ActorIsServiceAccount bool
}

// ListSecrets returns metadata only — path, current version, timestamps —
// for every active secret in OrganizationID that in.ActorUserID's roles
// hold a matching policy.ActionList policy for. Never a payload,
// ciphertext, nonce, or key ID: SecretMetadata has no field any of those
// could occupy.
//
// This is the one method that filters rather than allow/denies the whole
// call — see the objective's own LIST AUTHORIZATION section: a caller
// with secrets:list but no policy for a given path must never see that
// path's metadata, exactly the way an unauthorized GET /v1/secrets/{path}
// never reveals whether that path exists at all. Rules are resolved once
// (SecretPolicyService.FilterAllowedPaths), not once per secret in the
// list — see that method's own doc comment on why this scales with the
// caller's rule count, not the secret count.
func (s *SecretService) ListSecrets(ctx context.Context, in ListSecretsInput) ([]SecretMetadata, error) {
	if err := s.authorize(ctx, in.ActorUserID, in.ActorIsServiceAccount, permSecretsList); err != nil {
		return nil, err
	}
	list, err := s.repo.List(ctx, in.OrganizationID, in.Filter)
	if err != nil {
		return nil, err
	}

	paths := make([]string, len(list))
	for i, sec := range list {
		paths[i] = sec.Path
	}
	allowedPaths, err := s.policies.FilterAllowedPaths(ctx, in.ActorUserID, in.ActorIsServiceAccount, in.OrganizationID, paths, policy.ActionList)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(allowedPaths))
	for _, p := range allowedPaths {
		allowed[p] = true
	}

	out := make([]SecretMetadata, 0, len(list))
	for _, sec := range list {
		if !allowed[sec.Path] {
			continue
		}
		out = append(out, secretMetadataFromEntity(sec))
	}
	return out, nil
}

// authorize is the RBAC gate every method above calls first, before any
// database access — see this type's own doc comment for why this service
// performs this check itself rather than trusting a middleware layer that
// doesn't exist yet for it. An empty actorUserID (no authenticated
// identity at all) is rejected outright, the same as a real but
// insufficiently-privileged one — both return entity.ErrForbidden, so a
// caller can never distinguish "you're not logged in" from "you're logged
// in but not allowed" through this method's return value alone.
func (s *SecretService) authorize(ctx context.Context, actorUserID string, actorIsServiceAccount bool, permission string) error {
	if actorUserID == "" {
		return entity.ErrForbidden
	}
	var allowed bool
	var err error
	// Sprint 5 Task 1: a service account's ID only ever exists in
	// service_account_roles, never user_roles — see
	// RBACService.HasServiceAccountPermission's own doc comment. Getting
	// this dispatch wrong doesn't fail open: HasPermission on a
	// service-account ID simply finds no matching user_roles row and
	// correctly (if uselessly) denies, which is why this bug class is
	// "the feature doesn't work," not "the feature is insecure" — but it
	// must still be right for the feature to work at all.
	if actorIsServiceAccount {
		allowed, err = s.rbac.HasServiceAccountPermission(ctx, actorUserID, permission)
	} else {
		allowed, err = s.rbac.HasPermission(ctx, actorUserID, permission)
	}
	if err != nil {
		return err
	}
	if !allowed {
		return entity.ErrForbidden
	}
	return nil
}

// authorizeSecretAccess is Sprint 4 Task 2's layered authorization gate —
// every write and single-secret read method below calls this instead of
// authorize directly. It enforces, in order:
//
//  1. The existing global secrets:* permission check (authorize, above,
//     unchanged) — "If user lacks secrets:read, Result: DENY even if a
//     path policy exists," per the objective. A caller who fails this
//     step is rejected before a path is even normalized, exactly as
//     before this task.
//  2. Path normalization and validation (util.NormalizeSecretPath/
//     ValidateSecretPath — the same functions, and therefore the same
//     rules, CreateSecret/GetSecret/UpdateSecret/DeleteSecret already
//     applied before this task; nothing about canonicalization changed).
//  3. The new path-policy check (SecretPolicyService.Authorize) against
//     the canonical path — deny-by-default: a caller with the global
//     permission but no matching policy is still rejected.
//
// Returns the canonical path on success, so every caller below uses the
// exact same normalized string for its subsequent repository call — there
// is no way for the path a caller was authorized against to differ from
// the path it then acts on.
//
// A denial from either layer returns the identical entity.ErrForbidden a
// caller has always seen from this service — a client can no more
// distinguish "wrong permission" from "wrong path" than it could
// previously distinguish "not logged in" from "logged in but not
// allowed" (see authorize's own doc comment). This is deliberate: telling
// an unauthorized caller *which* layer rejected them, or that a path
// policy exists for that path at all, would be exactly the kind of
// "secret exists but you aren't allowed to access it" information leak
// the objective's ERROR RESPONSES section prohibits.
//
// A denial at either layer is audited (recordAccessDenied) before this
// returns — the objective's own AUDIT section requires denied secret
// access to be recorded (identity, action, canonical path, result,
// timestamp), which neither layer produced before this task: a rejected
// caller previously left no trail at all. The audited path is always the
// normalized one, even for a permission-layer denial reached before
// validation below — best-effort normalization purely for a readable
// audit row, never a claim that the raw input was itself valid.
func (s *SecretService) authorizeSecretAccess(ctx context.Context, actorUserID string, actorIsServiceAccount bool, organizationID, permission, rawPath, ipAddress string, action policy.Action) (string, error) {
	if err := s.authorize(ctx, actorUserID, actorIsServiceAccount, permission); err != nil {
		s.recordAccessDenied(ctx, actorUserID, actorIsServiceAccount, util.NormalizeSecretPath(rawPath), action, ipAddress)
		return "", err
	}

	path := util.NormalizeSecretPath(rawPath)
	if err := util.ValidateSecretPath(path); err != nil {
		return "", err
	}

	allowed, err := s.policies.Authorize(ctx, actorUserID, actorIsServiceAccount, organizationID, path, action)
	if err != nil {
		return "", err
	}
	if !allowed {
		s.recordAccessDenied(ctx, actorUserID, actorIsServiceAccount, path, action, ipAddress)
		return "", entity.ErrForbidden
	}
	return path, nil
}

// recordAccessDenied is authorizeSecretAccess's own denial-path audit
// call, best-effort like every other audit call in this service (see
// recordSecretAudit's own doc comment). metadata carries only the
// canonical path and the requested action — never a secret ID: whether a
// secret actually exists at this path is exactly what an unauthorized
// caller must not learn, even indirectly through its own audit trail row
// (see authorizeSecretAccess's own doc comment on that information-leak
// concern). action is recorded as "secret.access_denied" regardless of
// which layer rejected the caller, for the identical reason the returned
// error is always the same entity.ErrForbidden.
func (s *SecretService) recordAccessDenied(ctx context.Context, actorUserID string, actorIsServiceAccount bool, path string, action policy.Action, ipAddress string) {
	if s.auditTx == nil {
		return
	}
	actorType := entity.AuditActorUser
	if actorIsServiceAccount {
		actorType = entity.AuditActorServiceAccount
	}
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    actorType,
			ActorID:      strPtr(actorUserID),
			Action:       "secret.access_denied",
			ResourceType: strPtr("secret_path"),
			ResourceID:   strPtr(path),
			Result:       entity.AuditResultDenied,
			IPAddress:    strPtr(ipAddress),
			RequestID:    strPtr(util.RequestIDFromContext(ctx)),
			Metadata:     map[string]any{"path": path, "action": string(action)},
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record audit event",
			zap.String("action", "secret.access_denied"), zap.Error(err))
	}
}

// recordSecretAudit is best-effort — it never surfaces a failure to the
// caller, the same convention UserService.recordUserAudit already follows
// for every routine admin action (see that method's own doc comment).
// secret_versions (Phase 1) is itself the durable, timestamped record of
// what changed and who changed it; audit_logs is a separate observability
// trail describing that change, not its sole source of truth — contrast
// UserService.Register, where the audit entry and the row it describes
// commit or roll back together because no other durable trace of a
// registration exists anywhere else. That's also why this write doesn't
// need same-transaction atomicity with CreateWithFirstVersion/CreateVersionIfCurrent
// — which matters practically too: repository.SecretRepository cannot
// currently join an outer *sql.Tx (see secretRepository's own doc
// comment on why its db field is a concrete *sql.DB), so forcing atomicity
// here would require changes to Phase 1's repository this phase doesn't
// need to make.
//
// metadata never carries plaintext, ciphertext, a nonce, or key material —
// every call site above passes only path and version, both safe to sit in
// audit_logs.metadata indefinitely.
func (s *SecretService) recordSecretAudit(ctx context.Context, action, actorUserID string, actorIsServiceAccount bool, secret *entity.Secret, result entity.AuditResult, ipAddress string, metadata map[string]any) {
	if s.auditTx == nil {
		return
	}
	var actorID *string
	if actorUserID != "" {
		actorID = &actorUserID
	}
	actorType := entity.AuditActorUser
	if actorIsServiceAccount {
		actorType = entity.AuditActorServiceAccount
	}
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: &secret.OrganizationID,
			ActorType:      actorType,
			ActorID:        actorID,
			Action:         action,
			ResourceType:   strPtr("secret"),
			ResourceID:     strPtr(secret.ID),
			Result:         result,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record audit event",
			zap.String("action", action), zap.String("secret_id", secret.ID), zap.Error(err))
	}
}
