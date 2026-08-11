package service

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// SecretService is the service-layer boundary in front of
// repository.SecretRepository — Sprint 3 Phase 1 (the Secrets Engine's
// database foundation, migrations/000024). It owns path
// normalization/validation, the one piece of business logic this phase
// has; everything else is a thin pass-through. There is no encryption,
// KMS, REST/DTO translation, dynamic-secrets, rotation, or caching here —
// none of that exists yet (later, separate phases).
//
// Deliberately absent: any UpdateVersion-shaped method. That mirrors
// repository.SecretRepository's own interface exactly, so "a version can
// never be modified after creation, only superseded by a new one" holds
// because the type doesn't expose a way to violate it — not because
// callers remember not to.
type SecretService struct {
	secrets repository.SecretRepository
}

func NewSecretService(secrets repository.SecretRepository) *SecretService {
	return &SecretService{secrets: secrets}
}

// CreateSecretInput is CreateSecret's argument — a bare logical identity,
// with no version yet. Call PutVersion afterward to give it a first
// encrypted value.
type CreateSecretInput struct {
	OrganizationID string
	Path           string
	CreatedBy      string
}

func (s *SecretService) CreateSecret(ctx context.Context, in CreateSecretInput) (*entity.Secret, error) {
	path := util.NormalizeSecretPath(in.Path)
	if err := util.ValidateSecretPath(path); err != nil {
		return nil, err
	}
	secret := &entity.Secret{
		OrganizationID: in.OrganizationID,
		Path:           path,
		CreatedBy:      in.CreatedBy,
	}
	if err := s.secrets.Create(ctx, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (s *SecretService) GetSecret(ctx context.Context, id string) (*entity.Secret, error) {
	return s.secrets.GetByID(ctx, id)
}

func (s *SecretService) GetSecretByPath(ctx context.Context, organizationID, path string) (*entity.Secret, error) {
	return s.secrets.GetByPath(ctx, organizationID, util.NormalizeSecretPath(path))
}

func (s *SecretService) ListSecrets(ctx context.Context, organizationID string, f repository.SecretFilter) ([]*entity.Secret, error) {
	return s.secrets.List(ctx, organizationID, f)
}

// DeleteSecret soft-deletes the logical secret — its ciphertext and every
// version's ciphertext remain in storage (see migrations/000024's own doc
// comment on why); a separate, later permanent-purge operation is
// deliberately not implemented in this phase.
func (s *SecretService) DeleteSecret(ctx context.Context, id string) error {
	return s.secrets.SoftDelete(ctx, id)
}

// PutVersionInput is PutVersion's argument. Every field describing the
// encrypted payload is opaque here, exactly as it is on entity.SecretVersion
// — this service does not encrypt, decrypt, or interpret any of them.
type PutVersionInput struct {
	SecretID   string
	Ciphertext []byte
	Nonce      []byte
	AuthTag    []byte
	Algorithm  string
	WrappedDEK []byte
	KeyID      string
	KeyVersion *string
	CreatedBy  string
}

// PutVersion adds the next version of a secret's value — the only way this
// service ever changes what a secret "is". See
// repository.SecretRepository.CreateVersion for how the database
// guarantees the resulting version number is unique and sequential even
// under concurrent callers targeting the same secret.
func (s *SecretService) PutVersion(ctx context.Context, in PutVersionInput) (*entity.SecretVersion, error) {
	v := &entity.SecretVersion{
		SecretID:   in.SecretID,
		Ciphertext: in.Ciphertext,
		Nonce:      in.Nonce,
		AuthTag:    in.AuthTag,
		Algorithm:  in.Algorithm,
		WrappedDEK: in.WrappedDEK,
		KeyID:      in.KeyID,
		KeyVersion: in.KeyVersion,
		CreatedBy:  in.CreatedBy,
	}
	if err := s.secrets.CreateVersion(ctx, v); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *SecretService) GetVersion(ctx context.Context, secretID string, version int) (*entity.SecretVersion, error) {
	return s.secrets.GetVersion(ctx, secretID, version)
}

func (s *SecretService) GetCurrentVersion(ctx context.Context, secretID string) (*entity.SecretVersion, error) {
	return s.secrets.GetCurrentVersion(ctx, secretID)
}

func (s *SecretService) ListVersions(ctx context.Context, secretID string) ([]*entity.SecretVersion, error) {
	return s.secrets.ListVersions(ctx, secretID)
}

// DeleteVersion soft-deletes one specific version, independent of the
// parent secret's own deletion state (see entity.SecretVersion.IsDeleted's
// doc comment on the two separate deletion levels this schema supports).
func (s *SecretService) DeleteVersion(ctx context.Context, secretID string, version int) error {
	return s.secrets.SoftDeleteVersion(ctx, secretID, version)
}
