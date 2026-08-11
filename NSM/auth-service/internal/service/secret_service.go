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
	repo    repository.SecretRepository
	enc     *secrets.EncryptionService
	rbac    *RBACService
	auditTx AuditTxFunc
}

// NewSecretService constructs a SecretService. auditTx may be nil (the
// same allowance every other AuditTx dependency in this codebase makes) —
// every write still succeeds, it just doesn't get an audit trail entry.
func NewSecretService(repo repository.SecretRepository, enc *secrets.EncryptionService, rbac *RBACService, auditTx AuditTxFunc) *SecretService {
	return &SecretService{repo: repo, enc: enc, rbac: rbac, auditTx: auditTx}
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
	IPAddress      string
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
	if err := s.authorize(ctx, in.ActorUserID, permSecretsCreate); err != nil {
		return SecretMetadata{}, err
	}

	path := util.NormalizeSecretPath(in.Path)
	if err := util.ValidateSecretPath(path); err != nil {
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

	s.recordSecretAudit(ctx, "secret.created", in.ActorUserID, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path, "version": version.Version})
	return secretMetadataFromEntity(secret), nil
}

// GetSecretInput is GetSecret's argument. Version nil means "the current
// version"; a non-nil Version requests that specific historical version —
// see repository.SecretRepository.GetVersion/GetCurrentVersion, both of
// which this method delegates to unchanged.
type GetSecretInput struct {
	OrganizationID string
	Path           string
	Version        *int
	ActorUserID    string
	IPAddress      string
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
	if err := s.authorize(ctx, in.ActorUserID, permSecretsRead); err != nil {
		return SecretValue{}, err
	}

	path := util.NormalizeSecretPath(in.Path)
	if err := util.ValidateSecretPath(path); err != nil {
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

	s.recordSecretAudit(ctx, "secret.read", in.ActorUserID, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path, "version": version.Version})
	return SecretValue{Metadata: secretMetadataFromEntity(secret), Version: version.Version, Payload: payload}, nil
}

// UpdateSecretInput is UpdateSecret's argument. ExpectedVersion is
// required (must be positive) and must equal the secret's current
// version at the moment the update actually applies — see UpdateSecret's
// own doc comment for why this can never be optional.
type UpdateSecretInput struct {
	OrganizationID  string
	Path            string
	ExpectedVersion int
	Payload         map[string]string
	ActorUserID     string
	IPAddress       string
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
	if err := s.authorize(ctx, in.ActorUserID, permSecretsUpdate); err != nil {
		return SecretMetadata{}, err
	}
	if in.ExpectedVersion <= 0 {
		return SecretMetadata{}, fmt.Errorf("service: UpdateSecret requires a positive ExpectedVersion")
	}

	path := util.NormalizeSecretPath(in.Path)
	if err := util.ValidateSecretPath(path); err != nil {
		return SecretMetadata{}, err
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

	s.recordSecretAudit(ctx, "secret.updated", in.ActorUserID, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path, "version": version.Version})
	return secretMetadataFromEntity(secret), nil
}

// DeleteSecretInput is DeleteSecret's argument.
type DeleteSecretInput struct {
	OrganizationID string
	Path           string
	ActorUserID    string
	IPAddress      string
}

// DeleteSecret soft-deletes the logical secret (repository.SecretRepository.SoftDelete)
// — its ciphertext and every version's ciphertext remain in storage,
// exactly as migrations/000024 designed. After this call, GetSecret for
// this path returns entity.ErrNotFound (GetByPath already filters
// deleted_at IS NULL) — "normal read" cannot see a deleted secret.
// Permanent destruction is not implemented in this phase.
func (s *SecretService) DeleteSecret(ctx context.Context, in DeleteSecretInput) error {
	if err := s.authorize(ctx, in.ActorUserID, permSecretsDelete); err != nil {
		return err
	}

	path := util.NormalizeSecretPath(in.Path)
	if err := util.ValidateSecretPath(path); err != nil {
		return err
	}

	secret, err := s.repo.GetByPath(ctx, in.OrganizationID, path)
	if err != nil {
		return err
	}
	if err := s.repo.SoftDelete(ctx, secret.ID); err != nil {
		return err
	}

	s.recordSecretAudit(ctx, "secret.deleted", in.ActorUserID, secret, entity.AuditResultSuccess, in.IPAddress,
		map[string]any{"path": secret.Path})
	return nil
}

// ListSecretsInput is ListSecrets' argument.
type ListSecretsInput struct {
	OrganizationID string
	Filter         repository.SecretFilter
	ActorUserID    string
}

// ListSecrets returns metadata only — path, current version, timestamps —
// for every active secret in OrganizationID. Never a payload, ciphertext,
// nonce, or key ID: SecretMetadata has no field any of those could occupy.
func (s *SecretService) ListSecrets(ctx context.Context, in ListSecretsInput) ([]SecretMetadata, error) {
	if err := s.authorize(ctx, in.ActorUserID, permSecretsList); err != nil {
		return nil, err
	}
	list, err := s.repo.List(ctx, in.OrganizationID, in.Filter)
	if err != nil {
		return nil, err
	}
	out := make([]SecretMetadata, len(list))
	for i, sec := range list {
		out[i] = secretMetadataFromEntity(sec)
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
func (s *SecretService) authorize(ctx context.Context, actorUserID, permission string) error {
	if actorUserID == "" {
		return entity.ErrForbidden
	}
	allowed, err := s.rbac.HasPermission(ctx, actorUserID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return entity.ErrForbidden
	}
	return nil
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
func (s *SecretService) recordSecretAudit(ctx context.Context, action, actorUserID string, secret *entity.Secret, result entity.AuditResult, ipAddress string, metadata map[string]any) {
	if s.auditTx == nil {
		return
	}
	var actorID *string
	if actorUserID != "" {
		actorID = &actorUserID
	}
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: &secret.OrganizationID,
			ActorType:      entity.AuditActorUser,
			ActorID:        actorID,
			Action:         action,
			ResourceType:   strPtr("secret"),
			ResourceID:     strPtr(secret.ID),
			Result:         result,
			IPAddress:      strPtr(ipAddress),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record audit event",
			zap.String("action", action), zap.String("secret_id", secret.ID), zap.Error(err))
	}
}
