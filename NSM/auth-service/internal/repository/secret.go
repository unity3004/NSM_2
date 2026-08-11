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
	Create(ctx context.Context, s *entity.Secret) error
	GetByID(ctx context.Context, id string) (*entity.Secret, error)
	GetByPath(ctx context.Context, organizationID, path string) (*entity.Secret, error)
	List(ctx context.Context, organizationID string, f SecretFilter) ([]*entity.Secret, error)
	SoftDelete(ctx context.Context, id string) error

	// CreateVersion assigns and inserts the next version number for
	// v.SecretID (ignoring any Version the caller set) and advances the
	// parent secret's CurrentVersion to match, atomically — see
	// postgres.secretRepository.CreateVersion for how. On return, v.ID,
	// v.Version and v.CreatedAt are populated.
	CreateVersion(ctx context.Context, v *entity.SecretVersion) error
	GetVersion(ctx context.Context, secretID string, version int) (*entity.SecretVersion, error)
	GetCurrentVersion(ctx context.Context, secretID string) (*entity.SecretVersion, error)
	ListVersions(ctx context.Context, secretID string) ([]*entity.SecretVersion, error)
	SoftDeleteVersion(ctx context.Context, secretID string, version int) error
}

// SecretFilter narrows SecretRepository.List. Zero value means "no filter".
type SecretFilter struct {
	Cursor *string
	Limit  int
}
